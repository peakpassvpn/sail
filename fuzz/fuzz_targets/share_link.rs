#![no_main]

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use sail::config::share_link;

// Share links come from subscriptions anyone may serve.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(outbound) = share_link::parse(text) {
        assert!(outbound["type"].is_string() && outbound["tag"].is_string());
    }
    let (outbounds, _) = share_link::parse_subscription(text);
    let mut tags = HashSet::new();
    for outbound in &outbounds {
        let tag = outbound["tag"].as_str().expect("a tag");
        assert!(tags.insert(tag.to_string()), "tag [{}] twice", tag);
    }
});
