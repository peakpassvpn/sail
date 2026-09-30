//! sail's integration tests, as one test binary.
//!
//! Every file directly under `tests/` is linked as its own binary against the
//! whole of sail and its dependencies; one per protocol cost gigabytes of
//! debug builds and minutes of linking. A new test goes here as a module.
//! Tests stay a binary of their own under `tests/` when they need a process
//! to themselves or are run by name (`--test`): root, network namespaces, or
//! a single test thread.

mod common;
mod test_group_common;

mod test_amux_trojan;
mod test_anytls;
mod test_assets;
mod test_clash_api;
mod test_components;
mod test_config_clash;
mod test_config_surge;
mod test_corpus;
mod test_detour;
mod test_direct;
mod test_dns_respect_rules;
mod test_dns_server;
mod test_dns_upstreams;
mod test_domain_resolver;
mod test_fakeip;
mod test_fallback;
mod test_group_fallback;
mod test_group_load_balance;
mod test_group_selector;
mod test_group_smart;
mod test_group_urltest;
mod test_grpc_pool;
mod test_harness;
mod test_http_proxy;
mod test_hysteria2;
mod test_in_chain_1;
mod test_inbound_resources;
mod test_listen;
mod test_mixed;
mod test_mptp;
mod test_mux;
mod test_out_chain_1;
mod test_out_chain_10;
mod test_out_chain_2;
mod test_out_chain_3;
mod test_out_chain_4;
mod test_out_chain_5;
mod test_out_chain_6;
mod test_out_chain_7;
mod test_out_chain_8;
mod test_out_chain_9;
mod test_outbound_provider;
mod test_outbound_registry;
mod test_provider_retire;
mod test_quic_resources;
mod test_quic_trojan;
mod test_reality;
mod test_reload;
mod test_route_actions;
mod test_route_network;
mod test_route_on_demand;
mod test_route_pass;
mod test_route_sing_box;
mod test_rule_set;
mod test_shadowsocks;
mod test_shadowtls;
mod test_socks;
mod test_socks_udp;
mod test_ss2022;
mod test_tls_pin_sing_box;
mod test_tls_trojan;
mod test_transport_v2ray;
mod test_trojan;
mod test_tryall;
mod test_tuic;
mod test_udp_large;
mod test_uot;
mod test_vless;
mod test_vmess;
mod test_wireguard;
mod test_wireguard_endpoint;
mod test_wireguard_sing_box;
mod test_ws_amux_trojan;
mod test_ws_trojan;
