//! ECHConfigLists, as `tls.ech.config` and DNS give them.

use std::io;

/// An ECHConfigList from base64 or PEM. A lone ECHConfig gets the list's
/// length prefix.
pub(crate) fn decode_ech_config_list(ech_config_list: &str) -> io::Result<Vec<u8>> {
    let base64: String = ech_config_list
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let (list, _) = ensure_ech_config_list_bytes(decode_base64(&base64)?);
    Ok(list)
}

fn ensure_ech_config_list_bytes(mut decoded: Vec<u8>) -> (Vec<u8>, bool) {
    if decoded.len() >= 2 {
        let declared = u16::from_be_bytes([decoded[0], decoded[1]]) as usize;
        if declared == decoded.len().saturating_sub(2) {
            return (decoded, false);
        }
    }

    if decoded.len() >= 4 && decoded[0] == 0xfe && decoded[1] == 0x0d {
        let len = decoded.len();
        if u16::try_from(len).is_ok() {
            let mut wrapped = Vec::with_capacity(len + 2);
            wrapped.extend_from_slice(&(len as u16).to_be_bytes());
            wrapped.append(&mut decoded);
            return (wrapped, true);
        }
    }

    (decoded, false)
}

fn decode_base64(data: &str) -> io::Result<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }

    fn decode_chunk(chunk: &[u8; 4], output: &mut Vec<u8>) -> io::Result<()> {
        if chunk[0] == 64 || chunk[1] == 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            ));
        }
        output.push((chunk[0] << 2) | (chunk[1] >> 4));
        match (chunk[2], chunk[3]) {
            (64, 64) => Ok(()),
            (64, _) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            )),
            (c2, 64) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                Ok(())
            }
            (c2, c3) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                output.push(((c2 & 0x03) << 6) | c3);
                Ok(())
            }
        }
    }

    let mut output = Vec::with_capacity(data.len() * 3 / 4);
    let mut chunk = [0_u8; 4];
    let mut chunk_len = 0_usize;
    let mut seen_padding = false;

    for byte in data.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            seen_padding = true;
            chunk[chunk_len] = 64;
            chunk_len += 1;
        } else if let Some(decoded) = value(byte) {
            if seen_padding {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid base64 padding",
                ));
            }
            chunk[chunk_len] = decoded;
            chunk_len += 1;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 character",
            ));
        }

        if chunk_len == 4 {
            decode_chunk(&chunk, &mut output)?;
            chunk = [0_u8; 4];
            chunk_len = 0;
        }
    }

    match chunk_len {
        0 => Ok(output),
        2 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            Ok(output)
        }
        3 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push(((chunk[1] & 0x0f) << 4) | (chunk[2] >> 2));
            Ok(output)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid base64 length",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_base64, decode_ech_config_list, ensure_ech_config_list_bytes};

    #[test]
    fn test_decode_base64_standard_and_urlsafe() {
        assert_eq!(decode_base64("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_base64("AQI=").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("AQI").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("-_8=").unwrap(), vec![251, 255]);
    }

    #[test]
    fn test_decode_base64_invalid_input() {
        assert!(decode_base64("A").is_err());
        assert!(decode_base64("AA=A").is_err());
        assert!(decode_base64("AA$A").is_err());
    }

    #[test]
    fn test_ensure_ech_config_list_bytes_wrap_single_config() {
        let input = vec![0xfe, 0x0d, 0x00, 0x41];
        let (out, wrapped) = ensure_ech_config_list_bytes(input);
        assert!(wrapped);
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x04);
        assert_eq!(&out[2..], &[0xfe, 0x0d, 0x00, 0x41]);
    }

    #[test]
    fn test_ensure_ech_config_list_bytes_keep_existing_list() {
        let input = vec![0x00, 0x04, 0xfe, 0x0d, 0x00, 0x41];
        let (out, wrapped) = ensure_ech_config_list_bytes(input.clone());
        assert!(!wrapped);
        assert_eq!(out, input);
    }

    #[test]
    fn test_decode_ech_config_list_pem() {
        let pem = "-----BEGIN ECH CONFIGS-----\nAAT+DQBB\n-----END ECH CONFIGS-----";
        assert_eq!(
            decode_ech_config_list(pem).unwrap(),
            vec![0x00, 0x04, 0xfe, 0x0d, 0x00, 0x41]
        );
    }
}
