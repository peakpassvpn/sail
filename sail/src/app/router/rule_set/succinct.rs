//! The domain matcher of sing-box's binary rule-sets (`.srs`): a succinct
//! trie of the reversed domains, as that format lays it out, of the kind
//! github.com/openacid/succinct (MIT) describes. It is matched in its
//! compact form, not expanded into sets.

use anyhow::{anyhow, Result};

use super::reader::Reader;

/// Ends a key that matches any domain it is a suffix of, past a dot:
/// `.example.com`.
const PREFIX_LABEL: u8 = b'\r';
/// Ends a key that matches the domain and its subdomains: `example.com`
/// as a `domain_suffix`.
const ROOT_LABEL: u8 = b'\n';

pub(crate) struct Succinct {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    /// The ones before each word of `label_bitmap`, and their total.
    ranks: Vec<u32>,
    /// The position of every 32nd one of `label_bitmap`.
    selects: Vec<u32>,
}

impl Succinct {
    /// Reads the matcher as sing writes it: a version byte, then leaves,
    /// the label bitmap and the labels, each a uvarint count and its items.
    pub(crate) fn read(reader: &mut Reader) -> Result<Self> {
        reader.u8()?;
        let mut leaves = reader.u64_slice()?;
        let label_bitmap = reader.u64_slice()?;
        let labels = reader.bytes()?.to_vec();
        let ones: usize = label_bitmap.iter().map(|w| w.count_ones() as usize).sum();
        let last_one = label_bitmap
            .iter()
            .enumerate()
            .rev()
            .find(|(_, w)| **w != 0)
            .map(|(i, w)| (i << 6) | (63 - w.leading_zeros() as usize));
        let zeros = last_one.map_or(0, |l| l + 1 - ones);
        if last_one.is_none() || ones != zeros + 1 || labels.len() != zeros {
            return Err(anyhow!("domain: malformed succinct set"));
        }
        let leaf_words = ones.div_ceil(64);
        if leaves.len() < leaf_words {
            leaves.resize(leaf_words, 0);
        }
        let mut ranks = Vec::with_capacity(label_bitmap.len() + 1);
        let mut selects = Vec::new();
        let mut n = 0u32;
        for (i, word) in label_bitmap.iter().enumerate() {
            ranks.push(n);
            let mut w = *word;
            while w != 0 {
                if n.is_multiple_of(32) {
                    selects.push(((i << 6) + w.trailing_zeros() as usize) as u32);
                }
                n += 1;
                w &= w - 1;
            }
        }
        ranks.push(n);
        Ok(Self {
            leaves,
            label_bitmap,
            labels,
            ranks,
            selects,
        })
    }

    /// Whether `domain` matches one of the domains or suffixes.
    pub(crate) fn matches(&self, domain: &str) -> bool {
        let key: String = domain.chars().rev().collect();
        self.has(key.as_bytes())
    }

    fn has(&self, key: &[u8]) -> bool {
        let (mut node, mut at) = (0usize, 0usize);
        for &c in key {
            loop {
                if self.bit(&self.label_bitmap, at) {
                    return false;
                }
                let Some(label) = self.label(at, node) else {
                    return false;
                };
                if label == PREFIX_LABEL {
                    return true;
                }
                if label == ROOT_LABEL {
                    let next = self.zeros_before(at + 1);
                    if c == b'.' && self.bit(&self.leaves, next) {
                        return true;
                    }
                }
                if label == c {
                    break;
                }
                at += 1;
            }
            node = self.zeros_before(at + 1);
            let Some(one) = node.checked_sub(1).and_then(|i| self.select(i)) else {
                return false;
            };
            at = one + 1;
        }
        if self.bit(&self.leaves, node) {
            return true;
        }
        loop {
            if self.bit(&self.label_bitmap, at) {
                return false;
            }
            match self.label(at, node) {
                Some(PREFIX_LABEL | ROOT_LABEL) => return true,
                Some(_) => at += 1,
                None => return false,
            }
        }
    }

    fn label(&self, at: usize, node: usize) -> Option<u8> {
        at.checked_sub(node)
            .and_then(|i| self.labels.get(i))
            .copied()
    }

    /// Past the end reads as a one, which ends every walk.
    fn bit(&self, words: &[u64], i: usize) -> bool {
        words.get(i >> 6).is_none_or(|w| w & (1 << (i & 63)) != 0)
    }

    /// The zeros of the label bitmap before position `i`.
    fn zeros_before(&self, i: usize) -> usize {
        let word = i >> 6;
        let ones = match self.label_bitmap.get(word) {
            Some(w) => self.ranks[word] + (w & ((1u64 << (i & 63)) - 1)).count_ones(),
            None => self.ranks[self.label_bitmap.len()],
        };
        i - ones as usize
    }

    /// The position of the `i`th one of the label bitmap, from 0.
    fn select(&self, i: usize) -> Option<usize> {
        let mut word = (*self.selects.get(i >> 5)? >> 6) as usize;
        while word + 1 < self.ranks.len() && self.ranks[word + 1] as usize <= i {
            word += 1;
        }
        let mut w = *self.label_bitmap.get(word)?;
        for _ in 0..(i - self.ranks[word] as usize) {
            w &= w.wrapping_sub(1);
        }
        (w != 0).then(|| (word << 6) + w.trailing_zeros() as usize)
    }
}
