mod common;

// app(socks) -> (socks)sail(direct) -> echo at 127.0.0.1
//
// With a fakeip server whose range holds the echo server's address, that
// address is a fake IP no domain was handed out for: the connection is
// refused, as sing-box refuses it, not sent to the address. Without one,
// it goes through.
#[cfg(all(feature = "inbound-socks", feature = "outbound-direct"))]
#[test]
fn an_unknown_fake_ip_is_refused() -> anyhow::Result<()> {
    for (dns, refused) in [
        (
            serde_json::json!({ "servers": [
                { "type": "fakeip", "inet4_range": "127.0.0.0/8" }
            ] }),
            true,
        ),
        (serde_json::json!({}), false),
    ] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let config = serde_json::json!({
                "dns": dns,
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
                "outbounds": [{ "type": "direct" }]
            });
            common::test_configs(vec![config.to_string()], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), refused, "{}: {:?}", dns, result);
    }
    Ok(())
}
