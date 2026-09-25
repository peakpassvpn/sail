//! The padding scheme: how many of a session's first writes are split up or
//! padded out, and to which sizes.
//!
//! A scheme is lines of `key=value`. `stop=N` says padding ends at the N-th
//! write; `K=...` gives the sizes of write K as comma-separated `min-max`
//! ranges, each a record of that many bytes, and `c` marks, a check: once the
//! payload has run out, a write stops at the next check instead of sending
//! the records after it as padding. Write 0 is the authentication, which
//! takes the first size of its line as the length of its padding.
//!
//! The server sends its scheme to any client whose `padding-md5` differs, so
//! both ends match `anytls-go` and `sing-anytls` byte for byte in how the
//! text is read and hashed.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use md5::{Digest, Md5};
use rand::Rng;

/// The scheme every client starts with and every server defaults to.
pub const DEFAULT_SCHEME: &str = "stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

/// One element of a write's sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Size {
    /// A record of this many bytes.
    Record(usize),
    /// A check: stop here if nothing is left to send.
    Check,
}

/// The largest record a scheme may ask for: what the length of a waste
/// frame can carry, with its header.
const MAX_RECORD: u64 = u16::MAX as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Range {
    Between(u64, u64),
    Check,
}

/// A parsed padding scheme.
#[derive(Debug, Clone)]
pub struct PaddingScheme {
    /// The text as given, which is what is hashed and what a server sends.
    raw: Vec<u8>,
    md5: String,
    stop: u32,
    writes: HashMap<u32, Vec<Range>>,
}

impl PaddingScheme {
    /// The default scheme.
    pub fn default_scheme() -> Self {
        // The default scheme is a constant known to parse.
        Self::parse(DEFAULT_SCHEME.as_bytes()).expect("the default padding scheme parses")
    }

    /// Reads a scheme the way the reference implementations do: only a
    /// missing or unreadable `stop` makes it unusable, and a range that
    /// does not read is skipped. This is for schemes a server pushes.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let map = string_map(raw);
        let stop = map.get("stop")?.parse::<i64>().ok()?;
        let stop = u32::try_from(stop).unwrap_or(0);
        let mut writes = HashMap::new();
        for (key, value) in &map {
            let Ok(index) = key.parse::<u32>() else {
                continue;
            };
            let ranges = value
                .split(',')
                .filter_map(|range| parse_range(range).ok().flatten())
                .collect();
            writes.insert(index, ranges);
        }
        Some(PaddingScheme {
            raw: raw.to_vec(),
            md5: hex_md5(raw),
            stop,
            writes,
        })
    }

    /// Reads a scheme from a configuration, where anything that would be
    /// skipped is a mistake instead.
    pub fn parse_strict(raw: &str) -> Result<Self> {
        if raw.len() > u16::MAX as usize {
            return Err(anyhow!("longer than a frame can carry"));
        }
        let mut stop = None;
        for line in raw.split('\n') {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("line \"{}\" is not key=value", line))?;
            if key == "stop" {
                let n = value
                    .parse::<u32>()
                    .map_err(|_| anyhow!("stop: \"{}\" is not a number", value))?;
                stop = Some(n);
                continue;
            }
            key.parse::<u32>()
                .map_err(|_| anyhow!("key \"{}\" is neither stop nor a write number", key))?;
            for range in value.split(',') {
                parse_range(range).map_err(|e| anyhow!("{}: {}", key, e))?;
            }
        }
        if stop.is_none() {
            return Err(anyhow!("stop is missing"));
        }
        Self::parse(raw.as_bytes()).ok_or_else(|| anyhow!("does not parse"))
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The lowercase hex MD5 of the text, which a client reports.
    pub fn md5(&self) -> &str {
        &self.md5
    }

    /// The write at which padding ends.
    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// The sizes of write `pkt`, drawn at random from its ranges. Empty for
    /// a write the scheme says nothing about.
    pub fn sizes(&self, pkt: u32) -> Vec<Size> {
        let Some(ranges) = self.writes.get(&pkt) else {
            return Vec::new();
        };
        let mut rng = rand::thread_rng();
        ranges
            .iter()
            .map(|range| match *range {
                Range::Check => Size::Check,
                // As the reference draws it: from [min, max).
                Range::Between(min, max) if min == max => Size::Record(min as usize),
                Range::Between(min, max) => Size::Record(rng.gen_range(min..max) as usize),
            })
            .collect()
    }

    /// The length of the padding sent with the authentication.
    pub fn auth_padding(&self) -> usize {
        match self.sizes(0).first() {
            Some(Size::Record(n)) => *n,
            _ => 0,
        }
    }
}

/// One range: `Ok(None)` for one the reference would skip without saying,
/// an error for one that does not read at all.
fn parse_range(range: &str) -> Result<Option<Range>> {
    if range == "c" {
        return Ok(Some(Range::Check));
    }
    let (min, max) = range
        .split_once('-')
        .filter(|(_, max)| !max.contains('-'))
        .ok_or_else(|| anyhow!("\"{}\" is neither min-max nor c", range))?;
    let min = min
        .parse::<i64>()
        .map_err(|_| anyhow!("\"{}\": not a number", range))?;
    let max = max
        .parse::<i64>()
        .map_err(|_| anyhow!("\"{}\": not a number", range))?;
    let (min, max) = if min > max { (max, min) } else { (min, max) };
    if min <= 0 || max <= 0 {
        return Ok(None);
    }
    let (min, max) = (min as u64, max as u64);
    if max > MAX_RECORD {
        return Err(anyhow!("\"{}\": larger than {}", range, MAX_RECORD));
    }
    Ok(Some(Range::Between(min, max)))
}

/// `key=value` lines, as `util.StringMapFromBytes` reads them: a line
/// without `=` is ignored and the value runs to the end of the line.
pub fn string_map(raw: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(raw)
        .split('\n')
        .filter_map(|line| {
            line.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn hex_md5(raw: &[u8]) -> String {
    Md5::digest(raw)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_reads_and_hashes_as_the_reference() {
        let scheme = PaddingScheme::default_scheme();
        assert_eq!(scheme.stop(), 8);
        // The md5 of the default scheme's text, as sing-anytls computes it.
        assert_eq!(scheme.md5(), "75cff2ad89aadf5e257059ee571ebe11");
        assert_eq!(scheme.auth_padding(), 30);
        assert_eq!(scheme.sizes(3)[0], Size::Record(9));
        let two = scheme.sizes(2);
        assert_eq!(two.len(), 9);
        assert_eq!(two[1], Size::Check);
        match two[0] {
            Size::Record(n) => assert!((400..500).contains(&n)),
            Size::Check => panic!("expected a record"),
        }
        assert!(scheme.sizes(8).is_empty());
    }

    #[test]
    fn lenient_parse_skips_what_the_reference_skips() {
        let scheme = PaddingScheme::parse(b"stop=3\n0=5-5\n1=x-9,0-4,7-3,c\nnoise").unwrap();
        assert_eq!(scheme.stop(), 3);
        assert_eq!(scheme.auth_padding(), 5);
        let one = scheme.sizes(1);
        assert_eq!(one.len(), 2);
        match one[0] {
            Size::Record(n) => assert!((3..7).contains(&n)),
            Size::Check => panic!("expected a record"),
        }
        assert_eq!(one[1], Size::Check);
        assert!(PaddingScheme::parse(b"0=1-2").is_none());
        assert!(PaddingScheme::parse(b"stop=x").is_none());
        assert!(PaddingScheme::parse(b"").is_none());
    }

    #[test]
    fn strict_parse_rejects_mistakes() {
        assert!(PaddingScheme::parse_strict(DEFAULT_SCHEME).is_ok());
        assert!(PaddingScheme::parse_strict("stop=2\n0=1-2\n1=3").is_err());
        assert!(PaddingScheme::parse_strict("0=1-2").is_err());
        assert!(PaddingScheme::parse_strict("stop=2\nfoo=1-2").is_err());
        assert!(PaddingScheme::parse_strict("stop=2\n1=1-70000").is_err());
        assert!(PaddingScheme::parse_strict("stop=2\n1=1-2,d").is_err());
        assert!(PaddingScheme::parse_strict("stop=2\n\n1=1-2").is_err());
    }

    #[test]
    fn string_map_reads_as_the_reference() {
        let map = string_map(b"v=2\nclient=sing-box/1.13\npadding-md5=ab=cd\nbad");
        assert_eq!(map["v"], "2");
        assert_eq!(map["client"], "sing-box/1.13");
        assert_eq!(map["padding-md5"], "ab=cd");
        assert_eq!(map.len(), 3);
    }
}
