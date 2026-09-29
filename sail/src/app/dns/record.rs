//! DNS records as sing-box's configuration writes them, for `predefined`
//! answers and the `response_answer`, `response_ns` and `response_extra`
//! conditions: a line of a zone file (`localhost. IN A 127.0.0.1`), with a
//! TTL of 3600 unless it gives one, or the base64 of the record's wire
//! form.

use anyhow::{anyhow, Result};
use hickory_proto::rr::{Name, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use hickory_proto::serialize::txt::Parser;

/// sing-box's default TTL of a record written without one.
const DEFAULT_TTL: u32 = 3600;

/// The record `text` writes.
pub fn parse_record(text: &str) -> Result<Record> {
    if let Some(wire) = base64(text.trim()) {
        if let Ok(record) = Record::read(&mut BinDecoder::new(&wire)) {
            return Ok(record);
        }
    }
    let zone = format!("$TTL {}\n{}\n", DEFAULT_TTL, text.trim());
    let (_, sets) = Parser::new(zone.as_str(), None, Some(Name::root()))
        .parse()
        .map_err(|e| anyhow!("record \"{}\": {}", text, e))?;
    let mut records = sets
        .values()
        .flat_map(|set| set.records_without_rrsigs().cloned());
    match (records.next(), records.next()) {
        (Some(record), None) => Ok(record),
        (None, _) => Err(anyhow!("record \"{}\": empty", text)),
        (Some(_), Some(_)) => Err(anyhow!("record \"{}\": one record, not several", text)),
    }
}

/// Whether `a` and `b` are the same record, as miekg/dns's `IsDuplicate`
/// has it, which sing-box matches responses by: the same name, in any
/// case (as names compare), class, type and data; the TTL aside.
pub fn same_record(a: &Record, b: &Record) -> bool {
    a.name == b.name && a.dns_class == b.dns_class && a.data == b.data
}

/// `text` decoded as standard, padded base64; none if it is not.
fn base64(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let bytes = text.as_bytes();
    let padding = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    if padding > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes[..bytes.len() - padding].chunks(4) {
        let mut acc = 0u32;
        for &c in chunk {
            acc = acc << 6 | u32::from(value(c)?);
        }
        acc <<= 6 * (4 - chunk.len() as u32);
        let take = chunk.len() * 6 / 8;
        out.extend_from_slice(&acc.to_be_bytes()[1..1 + take]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{RData, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;

    #[test]
    fn sing_box_s_examples_parse() {
        let a = parse_record("localhost. IN A 127.0.0.1").unwrap();
        assert_eq!(a.name, Name::from_ascii("localhost.").unwrap());
        assert_eq!(a.record_type(), RecordType::A);
        assert_eq!(a.ttl, 3600);
        let aaaa = parse_record("localhost. 60 IN AAAA ::1").unwrap();
        assert_eq!((aaaa.record_type(), aaaa.ttl), (RecordType::AAAA, 60));
        let txt = parse_record(r#"localhost. IN TXT "Hello""#).unwrap();
        let RData::TXT(txt) = &txt.data else {
            panic!("{:?}", txt)
        };
        assert_eq!(txt.to_string(), "Hello");
        let wildcard = parse_record("*.example. IN CNAME target.example.").unwrap();
        assert!(wildcard.name.is_wildcard());
        // Its wire form, in base64.
        // AAEAAQ== is 00 01 00 01; a record's wire form, in base64, as
        // sing-box takes one.
        assert_eq!(base64("AAEAAQ=="), Some(vec![0, 1, 0, 1]));
        assert_eq!(base64("QQ=="), Some(b"A".to_vec()));
        assert_eq!(base64("QUI="), Some(b"AB".to_vec()));
        assert_eq!(base64("QUJD"), Some(b"ABC".to_vec()));
        assert_eq!(base64("QU!D"), None);
        let wire = encode(&a.to_bytes().unwrap());
        assert_eq!(parse_record(&wire).unwrap(), a);
    }

    fn encode(bytes: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut acc = 0u32;
            for (i, b) in chunk.iter().enumerate() {
                acc |= u32::from(*b) << (16 - 8 * i);
            }
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(TABLE[(acc >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn mistakes_are_errors() {
        for bad in [
            "",
            "localhost. IN A",
            "localhost. IN A 1.2.3",
            "not a record",
        ] {
            assert!(parse_record(bad).is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn records_are_the_same_whatever_the_ttl_or_case() {
        let a = parse_record("Example. 60 IN A 10.0.0.1").unwrap();
        let b = parse_record("example. 300 IN A 10.0.0.1").unwrap();
        let c = parse_record("example. IN A 10.0.0.2").unwrap();
        assert!(same_record(&a, &b));
        assert!(!same_record(&a, &c));
    }
}
