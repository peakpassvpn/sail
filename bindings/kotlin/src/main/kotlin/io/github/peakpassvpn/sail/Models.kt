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

/**
 * sail's JSON carries no version: it only grows, and what this binding does
 * not know of a newer sail (a field, a string value) is ignored. Every field
 * added from now on has a default, so that an older sail's JSON, without
 * it, decodes too.
 */
internal val json = Json { ignoreUnknownKeys = true }

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
    /** The domain it goes to: the destination's, else the name it was dialled as, else the one sniffed. */
    val host: String? = null,
    /** The domain a sniff found, from a TLS server name or an HTTP Host. */
    @SerialName("sniff_host") val sniffHost: String? = null,
    /** Where the name it was dialled as came from, `sniff` or `reverse_mapping`; null where it was dialled as asked. */
    @SerialName("dial_domain_source") val dialDomainSource: String? = null,
    val process: String? = null,
    val user: String? = null,
    /** Who opened it, as the host told (Android). */
    val uid: Long? = null,
    val packages: List<String> = emptyList(),
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

/** A connection whose owner the host is asked for. */
@Serializable
data class ConnectionQuery(val network: String, val source: String, val destination: String)

/** Who opened a connection, as the host tells sail. */
@Serializable
data class ConnectionOwner(val uid: Long, val user: String? = null, val packages: List<String> = emptyList())

@Serializable
data class Mode(val mode: String, val modes: List<String>)

@Serializable
data class LogLine(val level: String, val message: String, @SerialName("time_ms") val timeMs: Long)

/** A log event: `reset` drops the lines had so far. */
@Serializable
data class Log(val reset: Boolean, val lines: List<LogLine>, val dropped: Long)

@Serializable
data class InstanceCapabilities(
    /**
     * The sail release the instance runs: through a client, the tunnel
     * process's, which may differ from [Sail.capabilities]' after an update.
     */
    val version: String? = null,
    @SerialName("has_tun") val hasTun: Boolean,
    @SerialName("opens_tun") val opensTun: Boolean,
    @SerialName("protects_sockets") val protectsSockets: Boolean,
    @SerialName("needs_network") val needsNetwork: Boolean,
    @SerialName("has_modes") val hasModes: Boolean,
)

@Serializable
data class Capabilities(
    /** The sail release. */
    val version: String,
    /** The modules compiled in: what was built, not which calls there are. */
    val features: List<String>,
    /** The commit it was built from: a short hash, or `unknown`; null from a sail before it was told. */
    val commit: String? = null,
)

@Serializable
internal data class Connections(val connections: List<Connection>)

@Serializable
internal data class Outbounds(val outbounds: List<Outbound>)

/** An update's failure: when, and why (with no URL in it). */
@Serializable
data class UpdateFailure(@SerialName("at_ms") val atMs: Long, val error: String)

/** What a subscription's server says of it. */
@Serializable
data class Subscription(
    val upload: Long,
    val download: Long,
    val total: Long,
    @SerialName("expire_ms") val expireMs: Long? = null,
)

/** An outbound provider: its members are among the outbounds. */
@Serializable
data class Provider(
    val tag: String,
    /** remote, local or inline. */
    val source: String,
    val members: Long,
    @SerialName("updated_ms") val updatedMs: Long? = null,
    /** Null when it is not updated by itself. */
    @SerialName("next_update_ms") val nextUpdateMs: Long? = null,
    /** The last update's, null after a success. */
    val failure: UpdateFailure? = null,
    val subscription: Subscription? = null,
)

@Serializable
data class RuleSet(
    val tag: String,
    /** remote, local or inline. */
    val source: String,
    val format: String? = null,
    val behavior: String? = null,
    val rules: Long,
    @SerialName("updated_ms") val updatedMs: Long? = null,
    @SerialName("next_update_ms") val nextUpdateMs: Long? = null,
    val failure: UpdateFailure? = null,
)

@Serializable
internal data class Providers(val providers: List<Provider>)

@Serializable
internal data class RuleSets(@SerialName("rule_sets") val ruleSets: List<RuleSet>)
