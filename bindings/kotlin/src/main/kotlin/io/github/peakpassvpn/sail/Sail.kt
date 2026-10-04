package io.github.peakpassvpn.sail

import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.channels.trySendBlocking
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * What the host does for an instance; each is optional. Called on sail's
 * threads, never the main one: [protectSocket] as the instance dials
 * (Android's `VpnService.protect`), [openTun] while it starts, the service
 * ones when a client asks.
 */
data class Platform(
    val protectSocket: ((Int) -> Boolean)? = null,
    val openTun: ((String) -> Int)? = null,
    val serviceStop: (() -> Int)? = null,
    val serviceReload: (() -> Int)? = null,
    /**
     * Who opened a connection; null when the host cannot tell. Asked of
     * every connection as it is routed, on sail's threads: be quick. On
     * Android: `ConnectivityManager.getConnectionOwnerUid` (API 29+), then
     * `PackageManager.getPackagesForUid`.
     */
    val findConnectionOwner: ((ConnectionQuery) -> ConnectionOwner?)? = null,
)

/** What sail calls of a [Platform], from jni/sail_jni.c. */
internal class PlatformBridge(private val platform: Platform) {
    fun protectSocket(fd: Int): Boolean = platform.protectSocket?.invoke(fd) ?: true
    fun openTun(request: String): Int = platform.openTun?.invoke(request) ?: -1
    fun serviceStop(): Int = platform.serviceStop?.invoke() ?: 0
    fun serviceReload(): Int = platform.serviceReload?.invoke() ?: 0
    fun findConnectionOwner(query: String): String? = platform.findConnectionOwner
        ?.invoke(json.decodeFromString(query))
        ?.let { json.encodeToString(ConnectionOwner.serializer(), it) }
}

/** What sail calls of a subscription, from jni/sail_jni.c. */
internal class EventSink(
    private val event: (Int, String) -> Unit,
    private val released: () -> Unit,
) {
    fun onEvent(kind: Int, json: String) = event(kind, json)
    fun onRelease() = released()
}

/** The kinds of events, as sail.h numbers them. */
enum class EventKind(val code: Int) {
    STATE(1), LOG(2), STATUS(3), CONNECTIONS(4), OUTBOUNDS(5), NETWORK(6), DISCONNECTED(7),
    FAULT(8), ROUTED(9), DNS(10), GROUP(11), DIAL(12), USER(13),
}

/**
 * An instance, or a client reaching one in another process: the same calls
 * either way. [close] frees it: it stops, without waiting, and its
 * subscriptions end. docs/ffi.md is the contract this keeps.
 */
class Sail private constructor(private val handle: Long) : AutoCloseable {
    companion object {
        init {
            System.loadLibrary("sail_jni")
        }

        /**
         * Makes an instance, idle until started. [settings]: JSON, the
         * core's start settings and `log_lines`, `worker_threads`,
         * `stack_size`.
         */
        fun create(settings: String? = null, platform: Platform? = null): Sail = Sail(
            Native.instanceNew(
                settings,
                platform?.let { PlatformBridge(it) },
                platform?.protectSocket != null,
                platform?.openTun != null,
                platform?.serviceStop != null,
                platform?.serviceReload != null,
                platform?.findConnectionOwner != null,
            )
        )

        /** Connects to the command service an instance serves elsewhere. */
        fun connect(options: String): Sail = Sail(Native.clientConnect(options))

        fun capabilities(): Capabilities = json.decodeFromString(Native.capabilities())

        fun cancel(operation: Long) = Native.cancel(operation)
    }

    override fun close() = Native.instanceFree(handle)

    fun start(config: String) = Native.instanceStart(handle, config)
    fun startFile(path: String) = Native.instanceStartFile(handle, path)
    fun reload(config: String? = null) = Native.instanceReload(handle, config)

    /** [reload], telling what became of each inbound; in the tunnel process only. */
    fun reloadReport(config: String? = null): ReloadReport =
        json.decodeFromString(Native.instanceReloadReport(handle, config))
    fun stop(timeoutMs: Int = 10_000) = Native.instanceStop(handle, timeoutMs)
    fun serve(options: String?) = Native.instanceServe(handle, options)

    fun state(): State = json.decodeFromString(Native.instanceState(handle))

    /** What the last stop, or the end of the last run, could not end or undo; null before any stop. */
    fun stopReport(): StopReport? = json.decodeFromString(Native.instanceStopReport(handle))
    fun capabilities(): InstanceCapabilities = json.decodeFromString(Native.instanceCapabilities(handle))
    fun traffic(): Traffic = json.decodeFromString(Native.traffic(handle))
    fun connections(): List<Connection> =
        json.decodeFromString<Connections>(Native.connections(handle)).connections
    fun closeConnection(id: Long): Boolean = Native.closeConnection(handle, id)
    fun closeAllConnections(): Long = Native.closeAllConnections(handle)

    /** Adds an inbound, sing-box's JSON of one, while it runs; not kept past a reload or a start. */
    fun addInbound(inbound: String) = Native.addInbound(handle, inbound)

    /** Removes the inbound [tag], closing its connections; how many it closed. */
    fun removeInbound(tag: String): Long = Native.removeInbound(handle, tag)
    fun outbounds(): List<Outbound> = json.decodeFromString<Outbounds>(Native.outbounds(handle)).outbounds
    fun groups(): List<Outbound> = json.decodeFromString<Outbounds>(Native.groups(handle)).outbounds

    /** The outbound providers, in the configuration's order. */
    fun providers(): List<Provider> = json.decodeFromString<Providers>(Native.providers(handle)).providers
    /** Updates the provider [tag] now, and waits until its members are in place. */
    fun updateProvider(tag: String) = Native.updateProvider(handle, tag)
    fun ruleSets(): List<RuleSet> = json.decodeFromString<RuleSets>(Native.ruleSets(handle)).ruleSets
    /** Updates the remote rule-set [tag] now, and waits. */
    fun updateRuleSet(tag: String) = Native.updateRuleSet(handle, tag)

    /**
     * Connects to [host]:[port] through the outbound [outbound] alone, whatever
     * the rules say, and waits until it is connected. Returns one end of a
     * socket pair sail relays through the outbound: a stream for "tcp", one
     * message per datagram for "udp". The descriptor is the caller's: on
     * Android, ParcelFileDescriptor.adoptFd takes it; closing it ends the
     * connection. Through a client, unsupported.
     */
    fun dial(outbound: String, network: String, host: String, port: Int, timeoutMs: Int = 5_000): Int =
        Native.dial(handle, outbound, network, host, port, timeoutMs)

    fun select(group: String, member: String) = Native.select(handle, group, member)
    fun delay(tag: String, url: String? = null, timeoutMs: Int = 5_000): Long =
        Native.delay(handle, tag, url, timeoutMs)
    fun urlTest(tag: String, url: String? = null, timeoutMs: Int = 5_000): Long =
        Native.urlTest(handle, tag, url, timeoutMs)
    fun mode(): Mode = json.decodeFromString(Native.mode(handle))
    fun setMode(mode: String) = Native.setMode(handle, mode)
    fun setNetworkState(state: String) = Native.setNetworkState(handle, state)
    fun networkChanged(mtu: Int = 0) = Native.networkChanged(handle, mtu)
    fun clearLogs() = Native.clearLogs(handle)

    /**
     * The events of [kind], as sail's JSON. Collecting ends the subscription
     * when cancelled; the instance freed ends the flow; a client's lost
     * connection fails it with [SailException.IO].
     */
    fun events(kind: EventKind, options: String? = null): Flow<String> = callbackFlow {
        val sink = EventSink(
            event = { code, json ->
                if (code == EventKind.DISCONNECTED.code) {
                    close(SailException(SailException.IO, "disconnected: $json"))
                } else {
                    trySendBlocking(json)
                }
            },
            released = { channel.close() },
        )
        val subscription = Native.subscribe(handle, kind.code, options, sink)
        awaitClose { Native.unsubscribe(subscription) }
    }

    fun states(): Flow<State> = events(EventKind.STATE).map { json.decodeFromString(it) }

    fun logs(level: String? = null, backlog: Boolean = true): Flow<Log> {
        val options = buildString {
            append("{\"backlog\": ").append(backlog)
            if (level != null) append(", \"level\": \"").append(level).append('"')
            append('}')
        }
        return events(EventKind.LOG, options).map { json.decodeFromString(it) }
    }

    /** Each panic of a task of the instance; in the tunnel process only. */
    fun faults(): Flow<FaultEvent> = events(EventKind.FAULT).map { text ->
        val lagged = json.parseToJsonElement(text).jsonObject["lagged"]
        if (lagged != null) FaultEvent.Lagged(lagged.jsonPrimitive.long)
        else FaultEvent.Panicked(json.decodeFromString<Fault>(text))
    }

    /** Each connection once routed and dialled; in the tunnel process only. */
    fun routedConnections(): Flow<Told<Routed>> = told(EventKind.ROUTED)

    /** Each DNS query answered or failed; in the tunnel process only. */
    fun dnsExchanges(): Flow<Told<DnsExchange>> = told(EventKind.DNS)

    /** Each switch of a group's member; in the tunnel process only. */
    fun groupSwitches(): Flow<Told<GroupSwitch>> = told(EventKind.GROUP)

    /** Failed dials, a chain's once a second at most; in the tunnel process only. */
    fun dialFailures(): Flow<Told<DialFailed>> = told(EventKind.DIAL)

    /** What happens to users; in the tunnel process only. */
    fun userEvents(): Flow<Told<UserEvent>> = told(EventKind.USER)

    private inline fun <reified T> told(kind: EventKind): Flow<Told<T>> = events(kind).map { text ->
        val lagged = json.parseToJsonElement(text).jsonObject["lagged"]
        if (lagged != null) Told.Lagged(lagged.jsonPrimitive.long) else Told.Event(json.decodeFromString<T>(text))
    }

    fun statuses(intervalMs: Long = 1000): Flow<Status> =
        events(EventKind.STATUS, "{\"interval_ms\": $intervalMs}").map { json.decodeFromString(it) }

    fun outboundUpdates(intervalMs: Long = 250): Flow<List<Outbound>> =
        events(EventKind.OUTBOUNDS, "{\"interval_ms\": $intervalMs}")
            .map { json.decodeFromString<Outbounds>(it).outbounds }
}
