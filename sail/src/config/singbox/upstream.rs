//! What sing-box 1.14 accepts and sail does not implement, and how each is
//! treated. A field sing-box does not know either is left to the schema,
//! which rejects it as a mistake.

/// How a field sail does not implement is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Ignoring it would route or secure traffic otherwise than the
    /// configuration says: an error.
    Unsupported,
    /// Ignoring it changes no routing or security: a warning, and the field
    /// is dropped.
    Ignored,
}

use Tier::*;

/// A field by its path, `*` standing for any list index or object key. A
/// rule's field, `….rules.*.field`, is the field of the rules a logical one
/// combines too, however deep.
pub struct Field {
    pub path: &'static str,
    pub tier: Tier,
}

const fn f(path: &'static str, tier: Tier) -> Field {
    Field { path, tier }
}

/// Removed without a word: `$schema` only points editors at a schema.
pub const SILENT: &[&str] = &["$schema"];

/// The services, by type, whose absence changes nothing about the traffic:
/// sail does not run them, and drops them with a warning. It runs no other
/// service either, and any other is an error.
pub const IGNORED_SERVICES: &[&str] = &[
    // sing-box's gRPC API, for its clients and dashboard to watch and
    // control the instance.
    "api",
];

/// Objects sail has no counterpart for, dropped once the fields they held
/// are.
pub const EMPTIED: &[&str] = &["experimental.clash_api", "experimental"];

pub const FIELDS: &[Field] = &[
    // Top level.
    f("ntp", Ignored),
    f("certificate_providers", Unsupported),
    f("network_namespaces", Unsupported),
    // Only the rejected-response cache of the legacy address filter
    // fields, which sail does not have; deprecated in sing-box 1.14.
    f("experimental.cache_file.store_rdrc", Ignored),
    f("experimental.cache_file.rdrc_timeout", Ignored),
    // The Clash API is not served yet; its mode is kept.
    f("experimental.clash_api.external_controller", Ignored),
    f("experimental.clash_api.external_ui", Ignored),
    f("experimental.clash_api.external_ui_download_url", Ignored),
    f(
        "experimental.clash_api.external_ui_download_detour",
        Ignored,
    ),
    f("experimental.clash_api.secret", Ignored),
    f(
        "experimental.clash_api.access_control_allow_origin",
        Ignored,
    ),
    f(
        "experimental.clash_api.access_control_allow_private_network",
        Ignored,
    ),
    f("experimental.v2ray_api", Ignored),
    f("experimental.debug", Ignored),
    // DNS.
    // Each server's answers are kept apart, always: what this asked for.
    f("dns.independent_cache", Ignored),
    // DNS rule conditions and action options.
    f("dns.rules.*.query_client_subnet", Unsupported),
    f("dns.rules.*.query_dnssec", Unsupported),
    f("dns.rules.*.source_geoip", Unsupported),
    f("dns.rules.*.geoip", Unsupported),
    f("dns.rules.*.network_type", Unsupported),
    f("dns.rules.*.network_is_expensive", Unsupported),
    f("dns.rules.*.network_is_constrained", Unsupported),
    f("dns.rules.*.wifi_ssid", Unsupported),
    f("dns.rules.*.wifi_bssid", Unsupported),
    f("dns.rules.*.interface_address", Unsupported),
    f("dns.rules.*.network_interface_address", Unsupported),
    f("dns.rules.*.default_interface_address", Unsupported),
    f("dns.rules.*.source_mac_address", Unsupported),
    f("dns.rules.*.source_hostname", Unsupported),
    f("dns.rules.*.preferred_by", Unsupported),
    f("dns.rules.*.rule_set_ip_cidr_accept_empty", Unsupported),
    // Matched while its responses come: a race is won by the first rule
    // that matches.
    f("dns.rules.*.race", Unsupported),
    f("dns.rules.*.speculative", Ignored),
    f("dns.rules.*.method", Ignored),
    f("dns.rules.*.no_drop", Ignored),
    // HTTP clients: a download over HTTP/1.1 is the same download.
    f("http_clients.*.tls", Unsupported),
    f("http_clients.*.protect_path", Unsupported),
    f("http_clients.*.netns", Unsupported),
    f("http_clients.*.network_strategy", Unsupported),
    f("http_clients.*.network_type", Unsupported),
    f("http_clients.*.fallback_network_type", Unsupported),
    f("http_clients.*.fallback_delay", Unsupported),
    f("http_clients.*.engine", Ignored),
    f("http_clients.*.version", Ignored),
    f("http_clients.*.disable_version_fallback", Ignored),
    f("http_clients.*.idle_timeout", Ignored),
    f("http_clients.*.keep_alive_period", Ignored),
    f("http_clients.*.stream_receive_window", Ignored),
    f("http_clients.*.connection_receive_window", Ignored),
    f("http_clients.*.max_concurrent_streams", Ignored),
    f("http_clients.*.initial_packet_size", Ignored),
    f("http_clients.*.disable_path_mtu_discovery", Ignored),
    f("http_clients.*.bind_address_no_port", Ignored),
    f("http_clients.*.reuse_addr", Ignored),
    f("http_clients.*.disable_tcp_keep_alive", Ignored),
    f("http_clients.*.tcp_keep_alive", Ignored),
    f("http_clients.*.tcp_keep_alive_interval", Ignored),
    f("http_clients.*.tcp_fast_open", Ignored),
    f("http_clients.*.tcp_multi_path", Ignored),
    f("http_clients.*.udp_fragment", Ignored),
    f("route.rule_set.*.http_client.tls", Unsupported),
    f("route.rule_set.*.http_client.protect_path", Unsupported),
    f("route.rule_set.*.http_client.netns", Unsupported),
    f("route.rule_set.*.http_client.network_strategy", Unsupported),
    f("route.rule_set.*.http_client.network_type", Unsupported),
    f(
        "route.rule_set.*.http_client.fallback_network_type",
        Unsupported,
    ),
    f("route.rule_set.*.http_client.fallback_delay", Unsupported),
    f("route.rule_set.*.http_client.engine", Ignored),
    f("route.rule_set.*.http_client.version", Ignored),
    f(
        "route.rule_set.*.http_client.disable_version_fallback",
        Ignored,
    ),
    f("route.rule_set.*.http_client.idle_timeout", Ignored),
    f("route.rule_set.*.http_client.keep_alive_period", Ignored),
    f(
        "route.rule_set.*.http_client.stream_receive_window",
        Ignored,
    ),
    f(
        "route.rule_set.*.http_client.connection_receive_window",
        Ignored,
    ),
    f(
        "route.rule_set.*.http_client.max_concurrent_streams",
        Ignored,
    ),
    f("route.rule_set.*.http_client.initial_packet_size", Ignored),
    f(
        "route.rule_set.*.http_client.disable_path_mtu_discovery",
        Ignored,
    ),
    f("route.rule_set.*.http_client.bind_address_no_port", Ignored),
    f("route.rule_set.*.http_client.reuse_addr", Ignored),
    f(
        "route.rule_set.*.http_client.disable_tcp_keep_alive",
        Ignored,
    ),
    f("route.rule_set.*.http_client.tcp_keep_alive", Ignored),
    f(
        "route.rule_set.*.http_client.tcp_keep_alive_interval",
        Ignored,
    ),
    f("route.rule_set.*.http_client.tcp_fast_open", Ignored),
    f("route.rule_set.*.http_client.tcp_multi_path", Ignored),
    f("route.rule_set.*.http_client.udp_fragment", Ignored),
    // DNS servers.
    f("dns.servers.*.method", Unsupported),
    f("dns.servers.*.prefer_go", Ignored),
    f("dns.servers.*.neighbor_domain", Unsupported),
    f("dns.servers.*.netns", Unsupported),
    f("dns.servers.*.protect_path", Unsupported),
    f("dns.servers.*.network_strategy", Unsupported),
    f("dns.servers.*.network_type", Unsupported),
    f("dns.servers.*.fallback_network_type", Unsupported),
    f("dns.servers.*.fallback_delay", Unsupported),
    f("dns.servers.*.bind_address_no_port", Ignored),
    f("dns.servers.*.reuse_addr", Ignored),
    f("dns.servers.*.disable_tcp_keep_alive", Ignored),
    f("dns.servers.*.tcp_keep_alive", Ignored),
    f("dns.servers.*.tcp_keep_alive_interval", Ignored),
    f("dns.servers.*.tcp_fast_open", Ignored),
    f("dns.servers.*.tcp_multi_path", Ignored),
    f("dns.servers.*.udp_fragment", Ignored),
    f("dns.servers.*.tls.min_version", Unsupported),
    f("dns.servers.*.tls.max_version", Unsupported),
    f("dns.servers.*.tls.cipher_suites", Unsupported),
    f("dns.servers.*.tls.curve_preferences", Unsupported),
    f("dns.servers.*.tls.disable_sni", Unsupported),
    f(
        "dns.servers.*.tls.certificate_public_key_sha256",
        Unsupported,
    ),
    f("dns.servers.*.tls.client_certificate", Unsupported),
    f("dns.servers.*.tls.client_certificate_path", Unsupported),
    f("dns.servers.*.tls.client_key", Unsupported),
    f("dns.servers.*.tls.client_key_path", Unsupported),
    f("dns.servers.*.tls.fragment", Unsupported),
    f("dns.servers.*.tls.record_fragment", Unsupported),
    f("dns.servers.*.tls.engine", Ignored),
    f("dns.servers.*.tls.kernel_tx", Ignored),
    f("dns.servers.*.tls.kernel_rx", Ignored),
    f("dns.servers.*.tls.handshake_timeout", Ignored),
    // Routing.
    f("route.default_network_strategy", Unsupported),
    f("route.default_network_type", Unsupported),
    f("route.default_fallback_network_type", Unsupported),
    f("route.default_fallback_delay", Unsupported),
    f("route.find_process", Ignored),
    f("route.find_neighbor", Ignored),
    f("route.dhcp_lease_files", Ignored),
    f("route.override_android_vpn", Ignored),
    // Rule conditions.
    f("route.rules.*.client", Unsupported),
    f("route.rules.*.source_geoip", Unsupported),
    f("route.rules.*.network_type", Unsupported),
    f("route.rules.*.network_is_expensive", Unsupported),
    f("route.rules.*.network_is_constrained", Unsupported),
    f("route.rules.*.wifi_ssid", Unsupported),
    f("route.rules.*.wifi_bssid", Unsupported),
    f("route.rules.*.interface_address", Unsupported),
    f("route.rules.*.network_interface_address", Unsupported),
    f("route.rules.*.default_interface_address", Unsupported),
    f("route.rules.*.source_mac_address", Unsupported),
    f("route.rules.*.source_hostname", Unsupported),
    f("route.rules.*.preferred_by", Unsupported),
    // Rule action options.
    f("route.rules.*.network_strategy", Unsupported),
    f("route.rules.*.fallback_delay", Unsupported),
    f("route.rules.*.tls_spoof", Unsupported),
    f("route.rules.*.tls_spoof_method", Unsupported),
    f("route.rules.*.disable_cache", Unsupported),
    f("route.rules.*.disable_optimistic_cache", Unsupported),
    f("route.rules.*.rewrite_ttl", Unsupported),
    f("route.rules.*.client_subnet", Unsupported),
    // Listen fields.
    f("inbounds.*.bind_interface", Unsupported),
    f("inbounds.*.routing_mark", Unsupported),
    f("inbounds.*.netns", Unsupported),
    f("inbounds.*.detour", Unsupported),
    f("inbounds.*.proxy_protocol", Unsupported),
    f("inbounds.*.proxy_protocol_accept_no_header", Unsupported),
    f("inbounds.*.reuse_addr", Ignored),
    f("inbounds.*.tcp_fast_open", Ignored),
    f("inbounds.*.tcp_multi_path", Ignored),
    f("inbounds.*.udp_fragment", Ignored),
    // Dial fields.
    f("outbounds.*.protect_path", Unsupported),
    f("outbounds.*.netns", Unsupported),
    f("outbounds.*.network_strategy", Unsupported),
    f("outbounds.*.network_type", Unsupported),
    f("outbounds.*.fallback_network_type", Unsupported),
    f("outbounds.*.fallback_delay", Unsupported),
    f("outbounds.*.bind_address_no_port", Ignored),
    f("outbounds.*.reuse_addr", Ignored),
    f("outbounds.*.tcp_fast_open", Ignored),
    f("outbounds.*.tcp_multi_path", Ignored),
    f("outbounds.*.udp_fragment", Ignored),
    // TLS, both ways.
    f("*.*.tls.min_version", Unsupported),
    f("*.*.tls.max_version", Unsupported),
    f("*.*.tls.cipher_suites", Unsupported),
    f("*.*.tls.curve_preferences", Unsupported),
    f("*.*.tls.client_certificate", Unsupported),
    f("*.*.tls.client_certificate_path", Unsupported),
    f("*.*.tls.kernel_tx", Ignored),
    f("*.*.tls.kernel_rx", Ignored),
    f("*.*.tls.handshake_timeout", Ignored),
    // Inbound TLS.
    f("inbounds.*.tls.client_authentication", Unsupported),
    f(
        "inbounds.*.tls.client_certificate_public_key_sha256",
        Unsupported,
    ),
    f("inbounds.*.tls.certificate_provider", Unsupported),
    f("inbounds.*.tls.acme", Unsupported),
    f("inbounds.*.tls.ech", Unsupported),
    // Outbound TLS.
    f("outbounds.*.tls.engine", Ignored),
    f("outbounds.*.tls.disable_sni", Unsupported),
    f("outbounds.*.tls.certificate_public_key_sha256", Unsupported),
    f("outbounds.*.tls.client_key", Unsupported),
    f("outbounds.*.tls.client_key_path", Unsupported),
    f("outbounds.*.tls.fragment", Unsupported),
    f("outbounds.*.tls.fragment_fallback_delay", Unsupported),
    f("outbounds.*.tls.record_fragment", Unsupported),
    f("outbounds.*.tls.spoof", Unsupported),
    f("outbounds.*.tls.spoof_method", Unsupported),
    // TUN. One stack serves every `stack`; the platform proxy is the
    // host's to set.
    f("inbounds.*.stack", Ignored),
    f("inbounds.*.endpoint_independent_nat", Ignored),
    f("inbounds.*.platform", Ignored),
    // Filtering LAN clients by MAC address: not implemented.
    f("inbounds.*.include_mac_address", Unsupported),
    f("inbounds.*.exclude_mac_address", Unsupported),
];

/// Values sing-box accepts that sail does not implement: all of them change
/// routing.
pub const VALUES: &[(&str, &[&str])] = &[
    (
        "dns.servers.*.type",
        &[
            "dhcp",
            "mdns",
            "tailscale",
            "openconnect",
            "openvpn",
            "resolved",
        ],
    ),
    (
        "route.rules.*.action",
        &["evaluate", "respond", "direct", "predefined"],
    ),
    ("route.rules.*.sniffer", &["ssh", "rdp", "ntp"]),
];
