package io.github.peakpassvpn.sail.test

import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.system.OsConstants
import io.github.peakpassvpn.sail.ConnectionOwner
import io.github.peakpassvpn.sail.ConnectionQuery
import io.github.peakpassvpn.sail.Platform
import io.github.peakpassvpn.sail.Sail
import java.net.InetAddress
import java.net.InetSocketAddress
import org.json.JSONObject

/**
 * sail in a VpnService, as a host runs it (docs/ffi.md): it opens the TUN
 * sail asks for, applying the per-app lists of the request, protects the
 * sockets sail dials, tells sail who opened a connection, and follows the
 * network under the VPN, telling sail of it as it changes (as sing-box's
 * app does). The tests reach the running service through [running].
 */
class TestVpn : VpnService() {
    companion object {
        @Volatile
        var running: TestVpn? = null
            private set
    }

    /** The instance this service runs, while it does. */
    @Volatile
    var sail: Sail? = null
        private set

    /** The request of the last TUN opened, as sail sent it. */
    @Volatile
    var lastRequest: JSONObject? = null
        private set

    /** The network under the VPN, as last told to sail. */
    @Volatile
    var underlying: JSONObject? = null
        private set

    /** When sail was last told of the network, in ms of the uptime clock. */
    @Volatile
    var toldAt: Long = 0
        private set

    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastNetwork: Network? = null

    override fun onCreate() {
        super.onCreate()
        running = this
    }

    override fun onDestroy() {
        stopSail()
        running = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    /** Starts sail with [config]: a new instance each time. */
    fun startSail(config: String) {
        stopSail()
        val instance = Sail.create(
            platform = Platform(
                protectSocket = { fd -> protect(fd) },
                openTun = { request -> openTun(JSONObject(request)) },
                findConnectionOwner = { query -> owner(query) },
            ),
        )
        instance.start(config)
        sail = instance
        followNetwork()
    }

    /** Stops sail, which closes the TUN, and frees it. */
    fun stopSail() {
        networkCallback?.let {
            getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it)
        }
        networkCallback = null
        lastNetwork = null
        sail?.let {
            it.stop()
            it.close()
        }
        sail = null
    }

    /**
     * Follows the best network that is not a VPN, the one under ours: each
     * change is told to sail (`setNetworkState`), and a new network is also
     * a change the TUN's flows do not survive (`networkChanged`).
     */
    private fun followNetwork() {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                tell(network, caps, connectivity.getLinkProperties(network))
            }

            override fun onLinkPropertiesChanged(network: Network, link: LinkProperties) {
                tell(network, connectivity.getNetworkCapabilities(network), link)
            }
        }
        connectivity.registerBestMatchingNetworkCallback(
            request,
            callback,
            Handler(Looper.getMainLooper()),
        )
        networkCallback = callback
    }

    private fun tell(network: Network, caps: NetworkCapabilities?, link: LinkProperties?) {
        val instance = sail ?: return
        caps ?: return
        val type = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
        val state = JSONObject()
            .put("type", type)
            .put("interface", link?.interfaceName ?: "")
            .put("addresses", org.json.JSONArray(link?.linkAddresses?.map { it.toString() }.orEmpty()))
            .put("expensive", !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
        if (state.toString() == underlying?.toString()) return
        setUnderlyingNetworks(arrayOf(network))
        instance.setNetworkState(state.toString())
        val moved = lastNetwork != null && lastNetwork != network
        lastNetwork = network
        underlying = state
        toldAt = android.os.SystemClock.uptimeMillis()
        if (moved) instance.networkChanged()
    }

    /**
     * Who opened a connection, as the Platform KDoc says a host tells it:
     * the uid the system says, and its packages; null where it cannot.
     */
    private fun owner(query: ConnectionQuery): ConnectionOwner? {
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return null
        val protocol = if (query.network == "udp") OsConstants.IPPROTO_UDP else OsConstants.IPPROTO_TCP
        val uid = runCatching {
            connectivity.getConnectionOwnerUid(
                protocol,
                socketAddress(query.source),
                socketAddress(query.destination),
            )
        }.getOrNull() ?: return null
        if (uid < 0) return null
        val packages = packageManager.getPackagesForUid(uid)?.toList().orEmpty()
        return ConnectionOwner(uid.toLong(), packages = packages)
    }

    /** `1.2.3.4:5` or `[::1]:5`, as sail writes an address. */
    private fun socketAddress(text: String): InetSocketAddress {
        val colon = text.lastIndexOf(':')
        val host = text.substring(0, colon).removePrefix("[").removeSuffix("]")
        return InetSocketAddress(InetAddress.getByName(host), text.substring(colon + 1).toInt())
    }

    /** The TUN the request asks for, as sing-box's app opens it. */
    private fun openTun(request: JSONObject): Int {
        lastRequest = request
        val builder = Builder().setSession("sail test").setMtu(request.optInt("mtu", 9000))
        val route = request.optBoolean("auto_route", true)
        request.optString("ipv4").takeIf { it.isNotEmpty() && it != "null" }?.let { inet ->
            val (address, prefix) = inet.split("/")
            builder.addAddress(address, prefix.toInt())
            // The DNS server: the address after the TUN's, which sail answers.
            val parts = address.split(".").map { it.toInt() }
            builder.addDnsServer("${parts[0]}.${parts[1]}.${parts[2]}.${parts[3] + 1}")
            if (route) builder.addRoute("0.0.0.0", 0)
        }
        request.optString("ipv6").takeIf { it.isNotEmpty() && it != "null" }?.let { inet ->
            val (address, prefix) = inet.split("/")
            builder.addAddress(address, prefix.toInt())
            if (route) builder.addRoute("::", 0)
        }
        val include = request.optJSONArray("include_package")
        val exclude = request.optJSONArray("exclude_package")
        if (include != null && include.length() > 0) {
            for (i in 0 until include.length()) {
                runCatching { builder.addAllowedApplication(include.getString(i)) }
            }
        } else if (exclude != null && exclude.length() > 0) {
            for (i in 0 until exclude.length()) {
                runCatching { builder.addDisallowedApplication(exclude.getString(i)) }
            }
        }
        return builder.establish()?.detachFd() ?: -1
    }
}
