//! A YAML document as Mihomo reads it: maps keep their order, which some of
//! them mean (`nameserver-policy`), and scalars convert as Mihomo's weakly
//! typed decoding converts them (`port: "443"`, `udp: "true"`).

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// A YAML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Seq(Vec<Node>),
    Map(IndexMap<String, Node>),
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D: Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Node;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a YAML value")
            }

            fn visit_unit<E: de::Error>(self) -> std::result::Result<Node, E> {
                Ok(Node::Null)
            }

            fn visit_none<E: de::Error>(self) -> std::result::Result<Node, E> {
                Ok(Node::Null)
            }

            fn visit_some<D: Deserializer<'de>>(
                self,
                de: D,
            ) -> std::result::Result<Node, D::Error> {
                Node::deserialize(de)
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Node, E> {
                Ok(Node::Bool(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Node, E> {
                Ok(Node::Int(v))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Node, E> {
                match i64::try_from(v) {
                    Ok(v) => Ok(Node::Int(v)),
                    Err(_) => Ok(Node::Float(v as f64)),
                }
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Node, E> {
                Ok(Node::Float(v))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Node, E> {
                Ok(Node::Str(v.to_string()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Node, E> {
                Ok(Node::Str(v))
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Node, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Node::Seq(items))
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Node, A::Error> {
                let mut entries = IndexMap::new();
                while let Some((key, value)) = map.next_entry::<Node, Node>()? {
                    let key = match key {
                        Node::Str(s) => s,
                        Node::Int(i) => i.to_string(),
                        Node::Float(f) => f.to_string(),
                        Node::Bool(b) => b.to_string(),
                        Node::Null => "null".to_string(),
                        _ => return Err(de::Error::custom("a map key must be a scalar")),
                    };
                    entries.insert(key, value);
                }
                Ok(Node::Map(entries))
            }
        }

        de.deserialize_any(V)
    }
}

impl Node {
    /// What kind of value it is, as errors name it.
    pub fn kind(&self) -> &'static str {
        match self {
            Node::Null => "nothing",
            Node::Bool(_) => "a boolean",
            Node::Int(_) | Node::Float(_) => "a number",
            Node::Str(_) => "a string",
            Node::Seq(_) => "a list",
            Node::Map(_) => "a map",
        }
    }

    /// A string, as Mihomo takes one: numbers and booleans are written out.
    pub fn as_string(&self) -> Option<String> {
        match self {
            Node::Str(s) => Some(s.clone()),
            Node::Int(i) => Some(i.to_string()),
            Node::Float(f) => Some(f.to_string()),
            Node::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// A boolean, as Mihomo takes one: `"true"`, `1` and the like too.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Node::Bool(b) => Some(*b),
            Node::Int(i) => Some(*i != 0),
            Node::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "t" => Some(true),
                "false" | "0" | "f" | "" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    /// An integer, as Mihomo takes one: `"443"` too.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Node::Int(i) => Some(*i),
            Node::Float(f) if f.fract() == 0.0 => Some(*f as i64),
            Node::Str(s) => s.trim().parse().ok(),
            Node::Bool(b) => Some(*b as i64),
            _ => None,
        }
    }
}

/// Reads a YAML document. Aliases are expanded and merge keys (`<<`)
/// applied; the aliases may be many for their anchors, as templates reuse a
/// few anchors throughout.
pub fn parse(s: &str) -> Result<Node> {
    let mut budget = serde_saphyr::Budget::default();
    budget.alias_anchor_ratio_multiplier = 1_000;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    serde_saphyr::from_str_with_options(s, options).map_err(|e| anyhow!("{}", e))
}

/// The keys at the top of a document whose values hold an anchor
/// (`&name`): places to keep what aliases elsewhere repeat, which Mihomo
/// passes over and so does sail, without a word.
pub fn anchor_holders(s: &str) -> HashSet<String> {
    let mut holders = HashSet::new();
    let mut current: Option<String> = None;
    for line in s.lines() {
        let code = strip_comment(line);
        if code.trim().is_empty() {
            continue;
        }
        let top = !code.starts_with([' ', '\t', '-']);
        if top {
            current = code
                .split_once(':')
                .map(|(k, _)| k.trim().trim_matches(|c| c == '"' || c == '\'').to_string());
        }
        if let Some(key) = &current {
            if has_anchor(code) {
                holders.insert(key.clone());
            }
        }
    }
    holders
}

/// A line with its comment, if any, cut off: a `#` not in quotes and after
/// whitespace, or at its start.
fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    let mut prev = ' ';
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '#') if prev.is_whitespace() => return &line[..i],
            _ => {}
        }
        prev = c;
    }
    line
}

/// Whether a line defines an anchor: `&name` outside quotes, where a value
/// starts.
fn has_anchor(code: &str) -> bool {
    let mut quote = None;
    let mut prev = ' ';
    for c in code.chars() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '&') if prev.is_whitespace() || matches!(prev, ':' | '[' | '{' | ',' | '-') => {
                return true
            }
            _ => {}
        }
        prev = c;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_keeps_its_order_and_merges() {
        let doc = parse(
            "base: &b\n  type: select\n  interval: 300\n\
             groups:\n  - <<: *b\n    name: A\n    interval: 60\n\
             policy:\n  z.example: a\n  a.example: b\ntabbed:\t\n  k: v\n",
        )
        .unwrap();
        let Node::Map(root) = doc else { panic!() };
        let Node::Seq(groups) = &root["groups"] else {
            panic!()
        };
        let Node::Map(group) = &groups[0] else {
            panic!()
        };
        assert_eq!(group["type"], Node::Str("select".into()));
        assert_eq!(group["interval"], Node::Int(60));
        let Node::Map(policy) = &root["policy"] else {
            panic!()
        };
        assert_eq!(
            policy.keys().collect::<Vec<_>>(),
            ["z.example", "a.example"]
        );
    }

    #[test]
    fn scalars_convert_as_mihomo_s() {
        assert_eq!(Node::Str("443".into()).as_i64(), Some(443));
        assert_eq!(Node::Str("true".into()).as_bool(), Some(true));
        assert_eq!(Node::Int(1).as_bool(), Some(true));
        assert_eq!(Node::Int(8080).as_string(), Some("8080".into()));
        assert_eq!(Node::Seq(vec![]).as_string(), None);
    }

    #[test]
    fn anchor_holders_are_the_top_keys_with_anchors() {
        let holders = anchor_holders(
            "x-filter: &hk \"(?i)港|HK\"\n\
             p: &p {type: http, interval: 86400}\n\
             templates:\n  a: &a\n    lazy: true\n\
             mixed-port: 7890 # & not an anchor\n\
             name: \"a & b\"\n",
        );
        let mut holders: Vec<_> = holders.into_iter().collect();
        holders.sort();
        assert_eq!(holders, ["p", "templates", "x-filter"]);
    }
}
