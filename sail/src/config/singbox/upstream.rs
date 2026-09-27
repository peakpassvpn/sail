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
    f("dns.rules", Unsupported),
    f("dns.final", Unsupported),
    f("dns.client_subnet", Unsupported),
    f("dns.disable_cache", Ignored),
    f("dns.disable_expire", Ignored),
    f("dns.independent_cache", Ignored),
    f("dns.optimistic", Ignored),
    // Routing.
    f("route.rule_set", Unsupported),
    f("route.default_domain_resolver", Unsupported),
    f("route.default_network_strategy", Unsupported),
    f("route.default_network_type", Unsupported),
    f("route.default_fallback_network_type", Unsupported),
    f("route.default_fallback_delay", Unsupported),
    f("route.default_http_client", Unsupported),
    f("route.find_process", Ignored),
    f("route.find_neighbor", Ignored),
    f("route.dhcp_lease_files", Ignored),
    f("route.override_android_vpn", Ignored),
    // Rule conditions.
    f("route.rules.*.type", Unsupported),
    f("route.rules.*.mode", Unsupported),
    f("route.rules.*.rules", Unsupported),
    f("route.rules.*.invert", Unsupported),
    f("route.rules.*.ip_version", Unsupported),
    f("route.rules.*.protocol", Unsupported),
    f("route.rules.*.client", Unsupported),
    f("route.rules.*.domain_regex", Unsupported),
    f("route.rules.*.source_geoip", Unsupported),
    f("route.rules.*.source_ip_cidr", Unsupported),
    f("route.rules.*.source_ip_is_private", Unsupported),
    f("route.rules.*.ip_is_private", Unsupported),
    f("route.rules.*.source_port", Unsupported),
    f("route.rules.*.source_port_range", Unsupported),
    f("route.rules.*.process_path", Unsupported),
    f("route.rules.*.process_path_regex", Unsupported),
    f("route.rules.*.package_name", Unsupported),
    f("route.rules.*.package_name_regex", Unsupported),
    f("route.rules.*.user", Unsupported),
    f("route.rules.*.user_id", Unsupported),
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
    f("route.rules.*.rule_set", Unsupported),
    f("route.rules.*.rule_set_ip_cidr_match_source", Unsupported),
    f("route.rules.*.rule_set_ipcidr_match_source", Unsupported),
    // Rule action options.
    f("route.rules.*.override_address", Unsupported),
    f("route.rules.*.override_port", Unsupported),
    f("route.rules.*.network_strategy", Unsupported),
    f("route.rules.*.fallback_delay", Unsupported),
    f("route.rules.*.udp_disable_domain_unmapping", Unsupported),
    f("route.rules.*.udp_connect", Unsupported),
    f("route.rules.*.udp_timeout", Unsupported),
    f("route.rules.*.tls_fragment", Unsupported),
    f("route.rules.*.tls_fragment_fallback_delay", Unsupported),
    f("route.rules.*.tls_record_fragment", Unsupported),
    f("route.rules.*.tls_spoof", Unsupported),
    f("route.rules.*.tls_spoof_method", Unsupported),
    f("route.rules.*.method", Ignored),
    f("route.rules.*.no_drop", Ignored),
    f("route.rules.*.server", Unsupported),
    f("route.rules.*.strategy", Unsupported),
    f("route.rules.*.disable_cache", Ignored),
    f("route.rules.*.disable_optimistic_cache", Ignored),
    f("route.rules.*.rewrite_ttl", Ignored),
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
    f("outbounds.*.inet4_bind_address", Unsupported),
    f("outbounds.*.inet6_bind_address", Unsupported),
    f("outbounds.*.protect_path", Unsupported),
    f("outbounds.*.netns", Unsupported),
    f("outbounds.*.domain_resolver", Unsupported),
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
];

/// Values sing-box accepts that sail does not implement: all of them change
/// routing.
pub const VALUES: &[(&str, &[&str])] = &[
    (
        "route.rules.*.action",
        &[
            "route-options",
            "evaluate",
            "respond",
            "direct",
            "bypass",
            "hijack-dns",
            "predefined",
        ],
    ),
    (
        "route.rules.*.sniffer",
        &[
            "quic",
            "dns",
            "stun",
            "bittorrent",
            "dtls",
            "ssh",
            "rdp",
            "ntp",
        ],
    ),
];
