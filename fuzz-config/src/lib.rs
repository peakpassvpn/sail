//! Shared, side-effect-free harnesses for sail's public configuration parsers.

/// Keep individual allocations and recursive validation work bounded while
/// still allowing realistically large configurations.
pub const MAX_INPUT_LEN: usize = 256 * 1024;

/// Exercise the explicitly selected sing-box JSON/JSONC parser.
///
/// Returns whether the input reached the parser. Oversized and non-UTF-8
/// inputs cannot be supplied to the public `&str` API and return `false`.
#[must_use]
pub fn parse_json_bytes(data: &[u8]) -> bool {
    if data.len() > MAX_INPUT_LEN {
        return false;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let _ = std::hint::black_box(sail::config::Config::from_json(text));
    true
}

/// Exercise content-based format detection and the selected public parser.
#[must_use]
pub fn parse_auto_bytes(data: &[u8]) -> bool {
    if data.len() > MAX_INPUT_LEN {
        return false;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let _ = std::hint::black_box(sail::config::from_string(text));
    true
}

/// Exercise share-link subscription decoding and per-line import.
///
/// Returns whether the input reached the public `&str` API. Oversized and
/// non-UTF-8 inputs return `false` for the same reason as the config targets.
#[must_use]
pub fn parse_subscription_bytes(data: &[u8]) -> bool {
    if data.len() > MAX_INPUT_LEN {
        return false;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let _ = std::hint::black_box(sail::config::share_link::parse_subscription(text));
    true
}

fn bounded(data: &[u8]) -> bool {
    data.len() <= MAX_INPUT_LEN
}

/// Exercise source rule-set import without loading a file or URL.
#[must_use]
pub fn parse_rule_set_source_bytes(data: &[u8]) -> bool {
    if !bounded(data) {
        return false;
    }
    sail::fuzzing::rule_set_source(data);
    true
}

/// Exercise binary `.srs` import, including decompression and its reader.
#[must_use]
pub fn parse_rule_set_binary_bytes(data: &[u8]) -> bool {
    if !bounded(data) {
        return false;
    }
    sail::fuzzing::rule_set_binary(data);
    true
}

/// Exercise Mihomo's binary rule-set (`.mrs`) import: zstd, then its
/// domain trie or IP ranges.
#[must_use]
pub fn parse_rule_set_mrs_bytes(data: &[u8]) -> bool {
    if !bounded(data) {
        return false;
    }
    sail::fuzzing::rule_set_mrs(data);
    true
}

/// Exercise DNS messages with datagram and two-byte stream framing.
#[must_use]
pub fn parse_dns_message_bytes(data: &[u8]) -> bool {
    if !bounded(data) {
        return false;
    }
    sail::fuzzing::dns_message(data);
    true
}

/// Exercise stream and datagram protocol sniffing.
#[must_use]
pub fn parse_sniff_bytes(data: &[u8]) -> bool {
    if data.len() > sail::sniff::MAX_SNIFF_LEN {
        return false;
    }
    sail::fuzzing::sniff(data);
    true
}

/// Exercise synchronous inbound TUIC and XUDP wire decoders.
#[must_use]
pub fn parse_protocol_inbound_bytes(data: &[u8]) -> bool {
    if !bounded(data) {
        return false;
    }
    sail::fuzzing::inbound_protocol(data);
    true
}
