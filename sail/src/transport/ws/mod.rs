#[cfg(feature = "inbound-ws")]
pub mod inbound;
#[cfg(feature = "outbound-ws")]
pub mod outbound;

mod stream;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http::HeaderName;

/// Early data: the first bytes of the connection carried in the upgrade
/// request itself, sparing the round trip a handshake otherwise costs
/// before any of them can be sent. sing-box's `max_early_data` and
/// `early_data_header_name`.
///
/// The bytes are base64url without padding, as sing-box and Xray write them,
/// appended to the path when no header is named, or in the header named,
/// which is `Sec-WebSocket-Protocol` for Xray's clients.
#[derive(Debug, Clone, Default)]
pub struct EarlyData {
    /// How many bytes at most. Zero means none: the upgrade is sent at once.
    pub max: usize,
    pub header: Option<HeaderName>,
}

impl EarlyData {
    pub fn new(max: usize, header: Option<&str>) -> anyhow::Result<Self> {
        let header = match header {
            Some(name) => {
                if max == 0 {
                    return Err(anyhow::anyhow!(
                        "early_data_header_name: needs max_early_data"
                    ));
                }
                Some(HeaderName::try_from(name).map_err(|_| {
                    anyhow::anyhow!("early_data_header_name: invalid header name {:?}", name)
                })?)
            }
            None => None,
        };
        Ok(EarlyData { max, header })
    }

    pub fn enabled(&self) -> bool {
        self.max > 0
    }
}

pub fn encode_early_data(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes early data, refusing more than `max` bytes of it.
pub fn decode_early_data(encoded: &str, max: usize) -> Result<Vec<u8>, String> {
    // Four characters for every three bytes: anything longer than this is
    // over the limit before it is decoded.
    if encoded.len() > max.div_ceil(3) * 4 {
        return Err(format!("early data over {} bytes", max));
    }
    let data = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| format!("invalid early data: {}", e))?;
    if data.len() > max {
        return Err(format!("early data over {} bytes", max));
    }
    Ok(data)
}

/// The request target with early data in the path: appended to it, before
/// any query, as sing-box does.
pub fn target_with_early_data(path: &str, encoded: &str) -> String {
    match path.split_once('?') {
        Some((path, query)) => format!("{}{}?{}", path, encoded, query),
        None => format!("{}{}", path, encoded),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_early_data_encoding() {
        // base64url, no padding: `-` and `_` rather than `+` and `/`.
        assert_eq!(encode_early_data(&[0xfb, 0xff, 0xbf]), "-_-_");
        assert_eq!(encode_early_data(b"ab"), "YWI");
        assert_eq!(decode_early_data("YWI", 16).unwrap(), b"ab");
        assert_eq!(decode_early_data("", 16).unwrap(), b"");
        assert!(decode_early_data("YWI=", 16).is_err());
        assert!(decode_early_data("+/+/", 16).is_err());

        let data: Vec<u8> = (0..=255).collect();
        let encoded = encode_early_data(&data);
        assert_eq!(decode_early_data(&encoded, 256).unwrap(), data);
        assert!(decode_early_data(&encoded, 255).is_err());
    }

    #[test]
    fn test_target_with_early_data() {
        assert_eq!(target_with_early_data("/ws", "YWI"), "/wsYWI");
        assert_eq!(target_with_early_data("/ws?a=b", "YWI"), "/wsYWI?a=b");
    }

    #[test]
    fn test_early_data_config() {
        assert!(!EarlyData::new(0, None).unwrap().enabled());
        assert!(EarlyData::new(2048, Some("Sec-WebSocket-Protocol"))
            .unwrap()
            .enabled());
        assert!(EarlyData::new(0, Some("Sec-WebSocket-Protocol")).is_err());
        assert!(EarlyData::new(2048, Some("bad header")).is_err());
    }
}
