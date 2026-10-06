package io.github.peakpassvpn.sail.test

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * sail in a VpnService on an emulator: DNS, TCP and UDP through it to the
 * echo servers CI runs on the host (at the host's own address), the
 * apps it takes by package, and a stop and a start again. The test's own
 * app is the one whose traffic goes, or not, through the VPN.
 *
 * Arguments (instrumentation): `echoHost`, `tcpPort`, `udpPort`.
 */
@RunWith(AndroidJUnit4::class)
class VpnTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val args = InstrumentationRegistry.getArguments()
    private val echoHost = args.getString("echoHost")!!
    private val tcpPort = args.getString("tcpPort")!!.toInt()
    private val udpPort = args.getString("udpPort")!!.toInt()
    private val self = context.packageName

    /** sail's configuration: a TUN taking every address, `apps` its per-app field. */
    private fun config(apps: String = "") = """
        {
          "log": { "level": "debug" },
          "dns": { "servers": [
            { "type": "hosts", "tag": "hosts", "predefined": { "echo.test": "$echoHost" } }
          ] },
          "inbounds": [{
            "type": "tun", "tag": "tun-in",
            "address": ["172.19.0.1/30"],
            "auto_route": true $apps
          }],
          "outbounds": [{ "type": "direct", "tag": "direct" }],
          "route": { "rules": [{ "port": 53, "action": "hijack-dns" }] }
        }
    """.trimIndent()

    @Before
    fun consentAndService() {
        // The consent a user gives once, given by the shell instead, as
        // sing-box's tests do: no dialog.
        shell("appops set $self ACTIVATE_VPN allow")
        assertNull("the VPN still needs consent", VpnService.prepare(context))
        context.startService(Intent(context, TestVpn::class.java))
        waitFor("the service to start") { TestVpn.running != null }
    }

    @After
    fun stopService() {
        TestVpn.running?.stopSail()
        context.stopService(Intent(context, TestVpn::class.java))
    }

    private fun shell(command: String): String {
        val fd = instrumentation.uiAutomation.executeShellCommand(command)
        return android.os.ParcelFileDescriptor.AutoCloseInputStream(fd)
            .bufferedReader()
            .readText()
    }

    private fun waitFor(what: String, seconds: Int = 15, ok: () -> Boolean) {
        val until = System.currentTimeMillis() + seconds * 1000L
        while (!ok()) {
            if (System.currentTimeMillis() > until) throw AssertionError("waited for $what")
            Thread.sleep(100)
        }
    }

    private fun vpn(): TestVpn = TestVpn.running!!

    /** Whether this app's traffic goes through a VPN now. */
    private fun throughVpn(): Boolean {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val network = connectivity.activeNetwork ?: return false
        return connectivity.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    /**
     * Starts sail with [config], and waits for the system to send this
     * app's traffic through the VPN, or not, as [through] says: it does
     * a moment after the TUN is up.
     */
    private fun start(config: String, through: Boolean = true) {
        vpn().startSail(config)
        waitFor(if (through) "the VPN to carry this app" else "the VPN to leave this app") {
            throughVpn() == through
        }
    }

    /** A TCP round trip to the echo server, holding the socket open in [held]. */
    private fun tcpEcho(held: (Socket) -> Unit = {}) {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(echoHost, tcpPort), 5000)
            socket.soTimeout = 5000
            val sent = "sail tcp".toByteArray()
            socket.getOutputStream().write(sent)
            val got = ByteArray(sent.size)
            var read = 0
            while (read < got.size) {
                val n = socket.getInputStream().read(got, read, got.size - read)
                assertTrue("the echo ended", n > 0)
                read += n
            }
            assertArrayEquals(sent, got)
            held(socket)
        }
    }

    private fun udpEcho() {
        DatagramSocket().use { socket ->
            socket.soTimeout = 2000
            val sent = "sail udp".toByteArray()
            val to = InetSocketAddress(echoHost, udpPort)
            val got = DatagramPacket(ByteArray(64), 64)
            // UDP may be lost: a few tries.
            var answered = false
            for (attempt in 0 until 5) {
                socket.send(DatagramPacket(sent, sent.size, to))
                try {
                    socket.receive(got)
                    answered = true
                    break
                } catch (_: java.net.SocketTimeoutException) {
                }
            }
            assertTrue("no UDP echo", answered)
            assertArrayEquals(sent, got.data.copyOf(got.length))
        }
    }

    /** Whether sail lists a connection to the echo server's [port]. */
    private fun sailCarries(port: Int): Boolean =
        vpn().sail!!.connections().any { it.destination.endsWith(":$port") }

    @Test
    fun dnsTcpAndUdpGoThroughSail() {
        start(config())
        // The name only sail's hosts server knows.
        val resolved = InetAddress.getByName("echo.test").hostAddress
        assertEquals(echoHost, resolved)
        tcpEcho { waitFor("sail to list the TCP connection") { sailCarries(tcpPort) } }
        udpEcho()
        waitFor("sail to list the UDP session") { sailCarries(udpPort) }
    }

    /** The app's own package included: its traffic goes through sail. */
    @Test
    fun anIncludedAppGoesThroughSail() {
        start(config(""", "include_package": ["$self"]"""))
        val request = vpn().lastRequest!!
        assertEquals(self, request.getJSONArray("include_package").getString(0))
        tcpEcho {
            waitFor("sail to list the TCP connection") { sailCarries(tcpPort) }
            // Who opened it, as the service told sail (find_connection_owner).
            val listed = vpn().sail!!.connections().first { it.destination.endsWith(":$tcpPort") }
            assertTrue("owner not told: $listed", self in listed.packages)
        }
    }

    /** The app's own package excluded: its traffic goes around sail. */
    @Test
    fun anExcludedAppGoesAroundSail() {
        start(config(""", "exclude_package": ["$self"]"""), through = false)
        val request = vpn().lastRequest!!
        assertEquals(self, request.getJSONArray("exclude_package").getString(0))
        tcpEcho {
            Thread.sleep(1000)
            assertTrue("sail carried an excluded app's connection", !sailCarries(tcpPort))
        }
    }

    /** Stopped, sail closes the TUN; started again, it carries traffic again. */
    @Test
    fun aStopAndAStartAgain() {
        start(config())
        tcpEcho { waitFor("sail to list the TCP connection") { sailCarries(tcpPort) } }
        vpn().stopSail()
        assertNull(vpn().sail)
        waitFor("the VPN to go with the TUN") { !throughVpn() }
        start(config())
        assertNotNull(vpn().sail)
        tcpEcho { waitFor("sail to list the TCP connection again") { sailCarries(tcpPort) } }
        udpEcho()
    }
}
