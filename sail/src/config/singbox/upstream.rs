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

/// A field by its path, `*` standing for any list index or object key.
pub struct Field {
    pub path: &'static str,
    pub tier: Tier,
}

const fn f(path: &'static str, tier: Tier) -> Field {
    Field { path, tier }
}

/// Removed without a word: `$schema` only points editors at a schema.
pub const SILENT: &[&str] = &["$schema"];

/// Objects sail has no counterpart for, dropped once the fields they held
/// are.
pub const EMPTIED: &[&str] = &["experimental"];

pub const FIELDS: &[Field] = &[
    // Top level.
    f("ntp", Ignored),
    f("certificate", Unsupported),
    f("certificate_providers", Unsupported),
    f("http_clients", Unsupported),
    f("network_namespaces", Unsupported),
    f("services", Unsupported),
    f("experimental.cache_file", Ignored),
    f("experimental.clash_api", Ignored),
    f("experimental.v2ray_api", Ignored),
    f("experimental.debug", Ignored),
    // DNS.
    f("dns.client_subnet", Unsupported),
    f("dns.disable_cache", Ignored),
    f("dns.disable_expire", Ignored),
    f("dns.independent_cache", Ignored),
    f("dns.optimistic", Ignored),
    // A domain_resolver's options beyond its server and strategy.
    f("route.default_domain_resolver.timeout", Ignored),
    f("route.default_domain_resolver.disable_cache", Ignored),
    f(
        "route.default_domain_resolver.disable_optimistic_cache",
        Ignored,
    ),
    f("route.default_domain_resolver.rewrite_ttl", Ignored),
    f("route.default_domain_resolver.client_subnet", Unsupported),
    f("outbounds.*.domain_resolver.timeout", Ignored),
    f("outbounds.*.domain_resolver.disable_cache", Ignored),
    f(
        "outbounds.*.domain_resolver.disable_optimistic_cache",
        Ignored,
    ),
    f("outbounds.*.domain_resolver.rewrite_ttl", Ignored),
    f("outbounds.*.domain_resolver.client_subnet", Unsupported),
    f("endpoints.*.domain_resolver.timeout", Ignored),
    f("endpoints.*.domain_resolver.disable_cache", Ignored),
    f(
        "endpoints.*.domain_resolver.disable_optimistic_cache",
        Ignored,
    ),
    f("endpoints.*.domain_resolver.rewrite_ttl", Ignored),
    f("endpoints.*.domain_resolver.client_subnet", Unsupported),
    f("dns.servers.*.domain_resolver.timeout", Ignored),
    f("dns.servers.*.domain_resolver.disable_cache", Ignored),
    f(
        "dns.servers.*.domain_resolver.disable_optimistic_cache",
        Ignored,
    ),
    f("dns.servers.*.domain_resolver.rewrite_ttl", Ignored),
    f("dns.servers.*.domain_resolver.client_subnet", Unsupported),
    // DNS rule conditions and action options.
    f("dns.rules.*.query_client_subnet", Unsupported),
    f("dns.rules.*.query_dnssec", Unsupported),
    f("dns.rules.*.source_geoip", Unsupported),
    f("dns.rules.*.geoip", Unsupported),
    f("dns.rules.*.clash_mode", Unsupported),
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
    f("dns.rules.*.match_response", Unsupported),
    f("dns.rules.*.ip_cidr", Unsupported),
    f("dns.rules.*.ip_is_private", Unsupported),
    f("dns.rules.*.ip_accept_any", Unsupported),
    f("dns.rules.*.response_rcode", Unsupported),
    f("dns.rules.*.response_answer", Unsupported),
    f("dns.rules.*.response_ns", Unsupported),
    f("dns.rules.*.response_extra", Unsupported),
    f("dns.rules.*.client_subnet", Unsupported),
    f("dns.rules.*.remove_client_subnet", Unsupported),
    f("dns.rules.*.disable_cache", Ignored),
    f("dns.rules.*.disable_optimistic_cache", Ignored),
    f("dns.rules.*.rewrite_ttl", Ignored),
    f("dns.rules.*.timeout", Ignored),
    f("dns.rules.*.speculative", Ignored),
    f("dns.rules.*.method", Ignored),
    f("dns.rules.*.no_drop", Ignored),
    // DNS servers.
    f("dns.servers.*.headers", Unsupported),
    f("dns.servers.*.method", Unsupported),
    f("dns.servers.*.prefer_go", Ignored),
    f("dns.servers.*.neighbor_domain", Unsupported),
    f("dns.servers.*.netns", Unsupported),
    f("dns.servers.*.protect_path", Unsupported),
    f("dns.servers.*.domain_strategy", Unsupported),
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
    f("route.default_http_client", Unsupported),
    f("route.rule_set.*.http_client", Unsupported),
    f("route.find_process", Ignored),
    f("route.find_neighbor", Ignored),
    f("route.dhcp_lease_files", Ignored),
    f("route.override_android_vpn", Ignored),
    // Rule conditions.
    f("route.rules.*.client", Unsupported),
    f("route.rules.*.source_geoip", Unsupported),
    f("route.rules.*.clash_mode", Unsupported),
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
    f("inbounds.*.disable_tcp_keep_alive", Ignored),
    f("inbounds.*.tcp_keep_alive", Ignored),
    f("inbounds.*.tcp_keep_alive_interval", Ignored),
    f("inbounds.*.tcp_fast_open", Ignored),
    f("inbounds.*.tcp_multi_path", Ignored),
    f("inbounds.*.udp_fragment", Ignored),
    // Dial fields.
    f("outbounds.*.protect_path", Unsupported),
    f("outbounds.*.netns", Unsupported),
    f("outbounds.*.domain_strategy", Unsupported),
    f("outbounds.*.network_strategy", Unsupported),
    f("outbounds.*.network_type", Unsupported),
    f("outbounds.*.fallback_network_type", Unsupported),
    f("outbounds.*.fallback_delay", Unsupported),
    f("outbounds.*.bind_address_no_port", Ignored),
    f("outbounds.*.reuse_addr", Ignored),
    f("outbounds.*.disable_tcp_keep_alive", Ignored),
    f("outbounds.*.tcp_keep_alive", Ignored),
    f("outbounds.*.tcp_keep_alive_interval", Ignored),
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
    // Route management (roadmap 2.14): which traffic enters the TUN.
    f("inbounds.*.strict_route", Unsupported),
    f("inbounds.*.route_address", Unsupported),
    f("inbounds.*.route_exclude_address", Unsupported),
    f("inbounds.*.route_address_set", Unsupported),
    f("inbounds.*.route_exclude_address_set", Unsupported),
    f("inbounds.*.auto_redirect", Unsupported),
    f("inbounds.*.auto_redirect_input_mark", Unsupported),
    f("inbounds.*.auto_redirect_output_mark", Unsupported),
    f("inbounds.*.auto_redirect_reset_mark", Unsupported),
    f("inbounds.*.auto_redirect_nfqueue", Unsupported),
    f("inbounds.*.iproute2_table_index", Unsupported),
    f("inbounds.*.iproute2_rule_index", Unsupported),
    f("inbounds.*.loopback_address", Unsupported),
    f("inbounds.*.include_interface", Unsupported),
    f("inbounds.*.exclude_interface", Unsupported),
    f("inbounds.*.include_uid", Unsupported),
    f("inbounds.*.include_uid_range", Unsupported),
    f("inbounds.*.exclude_uid", Unsupported),
    f("inbounds.*.exclude_uid_range", Unsupported),
    f("inbounds.*.include_android_user", Unsupported),
    f("inbounds.*.include_package", Unsupported),
    f("inbounds.*.exclude_package", Unsupported),
    f("inbounds.*.include_mac_address", Unsupported),
    f("inbounds.*.exclude_mac_address", Unsupported),
    f("inbounds.*.exclude_mptcp", Unsupported),
];

/// Values sing-box accepts that sail does not implement: all of them change
/// routing.
pub const VALUES: &[(&str, &[&str])] = &[
    (
        "dns.rules.*.action",
        &["route-options", "evaluate", "respond", "predefined"],
    ),
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
        &["evaluate", "respond", "direct", "bypass", "predefined"],
    ),
    ("route.rules.*.sniffer", &["ssh", "rdp", "ntp"]),
];
