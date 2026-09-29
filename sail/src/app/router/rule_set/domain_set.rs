//! A set of domains kept as a succinct trie, and matched as it is: the form
//! Mihomo's MRS rule-sets hold their domains in.
//!
//! The trie is a level-order trie of the domains reversed, as described in
//! github.com/openacid/succinct (MIT; `sskv.go`): each node's outgoing
//! labels are packed in `labels`, a bitmap has a 0 for each label and a 1
//! closing each node's labels, and `leaves` marks the nodes that end a key.
//! The child a label at bit `i` leads to is the node numbered by the zeros
//! up to and including `i`; a node's labels start after the one closing the
//! node before it.
//!
//! Two labels are wildcards, as Mihomo writes its domain sets: `+`, which
//! ends a key `x.+` (the domain `+.x` reversed), matches whatever is left
//! of a domain past `x.`; `*` matches one label.

use anyhow::{anyhow, Result};

/// The domains of a domain set.
pub(crate) struct DomainSet {
    leaves: Vec<u64>,
    bitmap: Vec<u64>,
    labels: Vec<u8>,
    /// The ones in the bitmap before each of its words.
    ranks: Vec<u32>,
}

impl DomainSet {
    /// A set of the three parts. What they point at is checked as they are
    /// read, and what does not hold together matches nothing.
    pub(crate) fn new(leaves: Vec<u64>, bitmap: Vec<u64>, labels: Vec<u8>) -> Result<Self> {
        let mut ranks = Vec::with_capacity(bitmap.len() + 1);
        let mut ones = 0u32;
        for word in &bitmap {
            ranks.push(ones);
            ones = ones
                .checked_add(word.count_ones())
                .ok_or_else(|| anyhow!("a domain set too large"))?;
        }
        ranks.push(ones);
        Ok(DomainSet {
            leaves,
            bitmap,
            labels,
            ranks,
        })
    }

    /// How many domains it holds: its leaves.
    pub(crate) fn len(&self) -> usize {
        self.leaves.iter().map(|w| w.count_ones() as usize).sum()
    }

    fn bit(words: &[u64], i: usize) -> Option<bool> {
        words.get(i / 64).map(|w| w & (1 << (i % 64)) != 0)
    }

    /// The ones before bit `i`.
    fn rank(&self, i: usize) -> usize {
        let word = i / 64;
        let Some(&before) = self.ranks.get(word) else {
            return *self.ranks.last().unwrap_or(&0) as usize;
        };
        let partial = match self.bitmap.get(word) {
            Some(w) if !i.is_multiple_of(64) => (w & ((1u64 << (i % 64)) - 1)).count_ones(),
            _ => 0,
        };
        before as usize + partial as usize
    }

    /// Where the `n`th one (from 0) is.
    fn select(&self, n: usize) -> Option<usize> {
        let n = u32::try_from(n).ok()?;
        // The last word with fewer ones before it than `n + 1`.
        let word = self.ranks.partition_point(|&r| r <= n).checked_sub(1)?;
        let mut w = *self.bitmap.get(word)?;
        let mut left = n - self.ranks[word];
        while w != 0 {
            let bit = w.trailing_zeros() as usize;
            if left == 0 {
                return Some(word * 64 + bit);
            }
            left -= 1;
            w &= w - 1;
        }
        None
    }

    /// Where the labels of node `node` start in the bitmap.
    fn first_label(&self, node: usize) -> Option<usize> {
        match node {
            0 => Some(0),
            node => self.select(node - 1).map(|one| one + 1),
        }
    }

    /// The labels of `node`: each with its place in the bitmap.
    fn children(&self, node: usize) -> impl Iterator<Item = (u8, usize)> + '_ {
        let start = self.first_label(node);
        (start.unwrap_or(usize::MAX)..)
            .take_while(move |&i| start.is_some() && Self::bit(&self.bitmap, i) == Some(false))
            .filter_map(move |i| {
                // The label's index: the zeros before it.
                let label = *self.labels.get(i - self.rank(i))?;
                Some((label, i))
            })
    }

    /// The node the label at bit `i` leads to.
    fn child(&self, i: usize) -> usize {
        i + 1 - self.rank(i + 1)
    }

    fn leaf(&self, node: usize) -> bool {
        Self::bit(&self.leaves, node).unwrap_or(false)
    }

    /// Whether `domain` is in the set.
    pub(crate) fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        let reversed: Vec<u8> = domain.bytes().rev().collect();
        self.walk(0, &reversed, 0)
    }

    /// Whether what is left of `key`, from `at`, is in the set under `node`.
    fn walk(&self, node: usize, key: &[u8], at: usize) -> bool {
        if at == key.len() {
            return self.leaf(node);
        }
        for (label, i) in self.children(node) {
            match label {
                // Whatever is left, past the dot the key before it ends in.
                b'+' => return true,
                b'*' => {
                    let end = key[at..]
                        .iter()
                        .position(|&c| c == b'.')
                        .map_or(key.len(), |p| at + p);
                    if end > at && self.walk(self.child(i), key, end) {
                        return true;
                    }
                }
                label if label == key[at] && self.walk(self.child(i), key, at + 1) => {
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    /// Every key, as written in a domain set's text: for checking.
    #[cfg(test)]
    pub(crate) fn domains(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut key = Vec::new();
        self.collect(0, &mut key, &mut out);
        out
    }

    #[cfg(test)]
    fn collect(&self, node: usize, key: &mut Vec<u8>, out: &mut Vec<String>) {
        if self.leaf(node) {
            let mut domain = key.clone();
            if domain.last() == Some(&b'+') {
                domain.pop();
            }
            domain.reverse();
            out.push(String::from_utf8_lossy(&domain).to_string());
        }
        for (label, i) in self.children(node).collect::<Vec<_>>() {
            key.push(label);
            self.collect(self.child(i), key, out);
            key.pop();
        }
    }
}
