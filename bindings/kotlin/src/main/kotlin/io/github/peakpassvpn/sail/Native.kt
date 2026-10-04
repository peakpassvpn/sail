package io.github.peakpassvpn.sail

/** sail.h, as jni/sail_jni.c gives it to the JVM. */
internal object Native {
    @JvmStatic external fun instanceNew(
        settings: String?, bridge: PlatformBridge?,
        protect: Boolean, tun: Boolean, stop: Boolean, reload: Boolean, owner: Boolean,
    ): Long
    @JvmStatic external fun clientConnect(options: String): Long
    @JvmStatic external fun instanceFree(instance: Long)
    @JvmStatic external fun instanceStart(instance: Long, config: String)
    @JvmStatic external fun instanceStartFile(instance: Long, path: String)
    @JvmStatic external fun instanceReload(instance: Long, config: String?)
    @JvmStatic external fun instanceReloadReport(instance: Long, config: String?): String
    @JvmStatic external fun instanceServe(instance: Long, options: String?)
    @JvmStatic external fun instanceStop(instance: Long, timeoutMs: Int)
    @JvmStatic external fun instanceState(instance: Long): String
    @JvmStatic external fun instanceStopReport(instance: Long): String
    @JvmStatic external fun instanceCapabilities(instance: Long): String
    @JvmStatic external fun capabilities(): String
    @JvmStatic external fun traffic(instance: Long): String
    @JvmStatic external fun connections(instance: Long): String
    @JvmStatic external fun closeConnection(instance: Long, id: Long): Boolean
    @JvmStatic external fun closeAllConnections(instance: Long): Long
    @JvmStatic external fun outbounds(instance: Long): String
    @JvmStatic external fun groups(instance: Long): String
    @JvmStatic external fun providers(instance: Long): String
    @JvmStatic external fun updateProvider(instance: Long, tag: String)
    @JvmStatic external fun ruleSets(instance: Long): String
    @JvmStatic external fun updateRuleSet(instance: Long, tag: String)
    @JvmStatic external fun dial(
        instance: Long, outbound: String, network: String, host: String, port: Int, timeoutMs: Int,
    ): Int
    @JvmStatic external fun select(instance: Long, group: String, member: String)
    @JvmStatic external fun delay(instance: Long, tag: String, url: String?, timeoutMs: Int): Long
    @JvmStatic external fun urlTest(instance: Long, tag: String, url: String?, timeoutMs: Int): Long
    @JvmStatic external fun cancel(operation: Long)
    @JvmStatic external fun mode(instance: Long): String
    @JvmStatic external fun setMode(instance: Long, mode: String)
    @JvmStatic external fun setNetworkState(instance: Long, state: String)
    @JvmStatic external fun networkChanged(instance: Long, mtu: Int)
    @JvmStatic external fun clearLogs(instance: Long)
    @JvmStatic external fun subscribe(instance: Long, kind: Int, options: String?, sink: EventSink): Long
    @JvmStatic external fun unsubscribe(subscription: Long)
}
