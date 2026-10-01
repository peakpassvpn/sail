package io.github.peakpassvpn.sail

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** A call that failed: its SAIL_ERR_* code, and what sail said. */
class SailException(val code: Int, message: String) : Exception(message) {
    companion object {
        const val INVALID_ARGUMENT = 1
        const val NO_INSTANCE = 2
        const val STATE = 3
        const val CONFIG = 4
        const val IO = 5
        const val NOT_FOUND = 6
        const val UNSUPPORTED = 7
        const val CANCELLED = 8
        const val TIMEOUT = 9
        const val WRONG_THREAD = 10
        const val INTERNAL = 11
    }
}

internal val json = Json { ignoreUnknownKeys = false }

@Serializable
data class State(
    /** idle, starting, running, stopping, stopped or failed. */
    val state: String,
    val error: String? = null,
    @SerialName("started_at_ms") val startedAtMs: Long? = null,
)

@Serializable
data class Traffic(
    @SerialName("up_total") val upTotal: Long,
    @SerialName("down_total") val downTotal: Long,
    val connections: Int,
    val memory: Long,
)

/** A status event: the traffic, and its rate in bytes a second. */
@Serializable
data class Status(
    val up: Long,
    val down: Long,
    @SerialName("up_total") val upTotal: Long,
    @SerialName("down_total") val downTotal: Long,
    val connections: Int,
    val memory: Long,
)

@Serializable
data class Connection(
    val id: Long,
    val network: String,
    @SerialName("inbound_type") val inboundType: String,
    @SerialName("inbound_tag") val inboundTag: String,
    val source: String,
    val destination: String,
    val host: String? = null,
    val process: String? = null,
    val user: String? = null,
    val upload: Long,
    val download: Long,
    /** Unix seconds. */
    val start: Long,
    val chains: List<String>,
    val rule: String? = null,
)

@Serializable
data class Delay(
    @SerialName("time_ms") val timeMs: Long,
    /** null for a test that failed. */
    @SerialName("delay_ms") val delayMs: Long? = null,
)

@Serializable
data class Group(val selected: String, val members: List<String>, val selectable: Boolean)

@Serializable
data class Outbound(
    val tag: String,
    /** Mihomo's type name: Selector, Vless, Direct. */
    val kind: String,
    /** sing-box's type; null for a provider's member. */
    val protocol: String? = null,
    val provider: String? = null,
    val udp: Boolean,
    val history: List<Delay>,
    val group: Group? = null,
)

@Serializable
data class Mode(val mode: String, val modes: List<String>)

@Serializable
data class LogLine(val level: String, val message: String, @SerialName("time_ms") val timeMs: Long)

/** A log event: `reset` drops the lines had so far. */
@Serializable
data class Log(val reset: Boolean, val lines: List<LogLine>, val dropped: Long)

@Serializable
data class InstanceCapabilities(
    @SerialName("has_tun") val hasTun: Boolean,
    @SerialName("opens_tun") val opensTun: Boolean,
    @SerialName("protects_sockets") val protectsSockets: Boolean,
    @SerialName("needs_network") val needsNetwork: Boolean,
    @SerialName("has_modes") val hasModes: Boolean,
)

@Serializable
data class Capabilities(
    @SerialName("api_version") val apiVersion: Int,
    @SerialName("json_version") val jsonVersion: Int,
    val version: String,
    val features: List<String>,
)

@Serializable
internal data class Connections(val connections: List<Connection>)

@Serializable
internal data class Outbounds(val outbounds: List<Outbound>)
