//! A Clash map read field by field: each is taken as it is lowered, and what
//! is left over is sorted out as sail's policy has it.

use anyhow::{anyhow, Result};
use indexmap::IndexMap;

use super::node::Node;

/// How a field Mihomo takes and sail does not implement is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Ignoring it would route or secure traffic otherwise than the
    /// configuration says: an error.
    Unsupported,
    /// Ignoring it changes no routing or security: a warning.
    Ignored,
}

/// A map, with the path to it as errors write paths.
pub struct Fields {
    map: IndexMap<String, Node>,
    path: String,
}

impl Fields {
    /// The map `node`, at `path`.
    pub fn of(node: Node, path: &str) -> Result<Self> {
        match node {
            Node::Map(map) => Ok(Fields {
                map,
                path: path.to_string(),
            }),
            Node::Null => Ok(Fields {
                map: IndexMap::new(),
                path: path.to_string(),
            }),
            other => Err(anyhow!("{}: a map, not {}", path, other.kind())),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// The path of `key` in it.
    pub fn at(&self, key: &str) -> String {
        if self.path.is_empty() {
            key.to_string()
        } else {
            format!("{}.{}", self.path, key)
        }
    }

    /// The keys not taken yet, in order.
    pub fn keys(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }

    /// Puts `value` under `key`, for a reader after this one.
    pub fn put(&mut self, key: &str, value: Node) {
        self.map.insert(key.to_string(), value);
    }

    /// Whether it has `key`, taken or not yet.
    pub fn has(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// Takes `key`; a null value is no value, as Mihomo has it.
    pub fn take(&mut self, key: &str) -> Option<Node> {
        match self.map.shift_remove(key) {
            None | Some(Node::Null) => None,
            Some(node) => Some(node),
        }
    }

    pub fn string(&mut self, key: &str) -> Result<Option<String>> {
        self.take(key)
            .map(|n| {
                n.as_string()
                    .ok_or_else(|| anyhow!("{}: a string, not {}", self.at(key), n.kind()))
            })
            .transpose()
    }

    pub fn bool(&mut self, key: &str) -> Result<Option<bool>> {
        self.take(key)
            .map(|n| {
                n.as_bool()
                    .ok_or_else(|| anyhow!("{}: true or false, not {}", self.at(key), n.kind()))
            })
            .transpose()
    }

    /// An integer, within `T`'s range.
    pub fn int<T: TryFrom<i64>>(&mut self, key: &str) -> Result<Option<T>> {
        self.take(key)
            .map(|n| {
                n.as_i64()
                    .and_then(|i| T::try_from(i).ok())
                    .ok_or_else(|| anyhow!("{}: not a number in range", self.at(key)))
            })
            .transpose()
    }

    /// A list of strings; a single string is a list of one, as Mihomo
    /// takes it for most lists.
    pub fn strings(&mut self, key: &str) -> Result<Vec<String>> {
        let at = self.at(key);
        match self.take(key) {
            None => Ok(Vec::new()),
            Some(Node::Seq(items)) => items
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    n.as_string()
                        .ok_or_else(|| anyhow!("{}[{}]: a string, not {}", at, i, n.kind()))
                })
                .collect(),
            Some(n) => n
                .as_string()
                .map(|s| vec![s])
                .ok_or_else(|| anyhow!("{}: a list, not {}", at, n.kind())),
        }
    }

    /// A map within, to read field by field.
    pub fn map(&mut self, key: &str) -> Result<Option<Fields>> {
        let at = self.at(key);
        self.take(key).map(|n| Fields::of(n, &at)).transpose()
    }

    /// A list within, of what it holds.
    pub fn list(&mut self, key: &str) -> Result<Vec<Node>> {
        match self.take(key) {
            None => Ok(Vec::new()),
            Some(Node::Seq(items)) => Ok(items),
            Some(n) => Err(anyhow!("{}: a list, not {}", self.at(key), n.kind())),
        }
    }

    /// Sorts out what is left: a field `known` lists is Mihomo's, and is an
    /// error or a warning as its tier says; any other Mihomo does not know
    /// either, and is a warning, but where `silent` says to pass it over.
    pub fn finish(
        self,
        known: &[(&str, Tier)],
        silent: impl Fn(&str) -> bool,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        for (key, _) in &self.map {
            let at = self.at(key);
            match known.iter().find(|(k, _)| k == key) {
                Some((_, Tier::Unsupported)) => {
                    return Err(anyhow!("{}: sail does not implement this field yet", at));
                }
                Some((_, Tier::Ignored)) => {
                    warnings.push(format!(
                        "{}: sail does not implement this field; ignored",
                        at
                    ));
                }
                None if silent(key) => {}
                None => warnings.push(format!("{}: not a field Mihomo takes; ignored", at)),
            }
        }
        Ok(())
    }
}
