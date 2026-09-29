//! `hosts`, and the system's, as DNS rules before every other: as Mihomo
//! answers A and AAAA queries from them before any server, and resolves
//! with them whatever it dials. A name may be a pattern (`+.a`, `.a`, a
//! `*` label) and may stand for another name, which sail's hosts servers
//! take as Mihomo does; answers live 10 seconds, as Mihomo's.
//!
//! The system's hosts are read with the DNS module on and `use-system-hosts`
//! not off; with it off, names resolve as the system resolves them, hosts
//! and all. With `use-hosts: false`, Mihomo answers DNS queries without
//! them, but still dials with them; sail does both with them.
//!
//! Where sail does otherwise: a connection to a name that stands for
//! another is routed by its own name, and dialled at the other's addresses;
//! Mihomo routes it by the other.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::Fields;
use super::node::Node;
use super::provider::domains;
use super::Lowered;

/// The server of `hosts`, and that of the system's.
const HOSTS: &str = "hosts";
const SYSTEM_HOSTS: &str = "system-hosts";
/// How long an answer from hosts lives: Mihomo's.
const TTL: u32 = 10;

/// What is read of `hosts`, before the DNS section is lowered.
pub struct Hosts {
    /// The names, and what they are given.
    names: Map<String, Value>,
    /// Whether the system's hosts are read too.
    system: bool,
}

/// Reads `hosts`, and of the DNS section, whether the system's are read.
pub fn read(doc: &mut Fields, warnings: &mut Vec<String>) -> Result<Hosts> {
    let mut names = Map::new();
    if let Some(mut f) = doc.map("hosts")? {
        for name in f.keys() {
            let at = f.at(&name);
            let value = match f.take(&name) {
                Some(Node::Str(s)) => json!(s),
                Some(Node::Seq(items)) if !items.is_empty() => Value::Array(
                    items
                        .iter()
                        .map(|i| {
                            i.as_string()
                                .map(Value::String)
                                .ok_or_else(|| anyhow!("{}: addresses, not {}", at, i.kind()))
                        })
                        .collect::<Result<_>>()?,
                ),
                Some(other) => {
                    return Err(anyhow!(
                        "{}: an address, addresses or a name, not {}",
                        at,
                        other.kind()
                    ))
                }
                None => continue,
            };
            names.insert(name.to_ascii_lowercase(), value);
        }
        f.finish(&[], |_| false, warnings)?;
    }
    // Peeked, for the DNS section to take as it takes the rest.
    let system = match doc.take("dns") {
        Some(dns) => {
            let field = |key: &str| match &dns {
                Node::Map(m) => m.get(key).and_then(Node::as_bool),
                _ => None,
            };
            let system = field("enable") == Some(true) && field("use-system-hosts") != Some(false);
            doc.put("dns", dns);
            system
        }
        None => false,
    };
    Ok(Hosts { names, system })
}

impl Hosts {
    /// Puts the servers and rules of the hosts before the DNS section's.
    pub fn apply(self, out: &mut Lowered) -> Result<()> {
        let mut servers = Vec::new();
        let mut rules = Vec::new();
        let types = json!(["A", "AAAA"]);
        if !self.names.is_empty() {
            let patterns: Vec<String> = self.names.keys().cloned().collect();
            let mut rule = domains(&patterns);
            rule.insert("query_type".into(), types.clone());
            rule.insert("server".into(), json!(HOSTS));
            rule.insert("rewrite_ttl".into(), json!(TTL));
            rules.push(Value::Object(rule));
            servers.push(json!({
                "type": "hosts",
                "tag": HOSTS,
                "predefined": Value::Object(self.names),
            }));
        }
        if self.system {
            servers.push(json!({ "type": "hosts", "tag": SYSTEM_HOSTS }));
            rules.push(json!({
                "query_type": types,
                "action": "evaluate",
                "server": SYSTEM_HOSTS,
                "rewrite_ttl": TTL,
            }));
            rules.push(json!({
                "match_response": true,
                "ip_accept_any": true,
                "action": "respond",
            }));
        }
        if servers.is_empty() {
            return Ok(());
        }
        let list = |key: &str, dns: &mut Map<String, Value>| -> Result<Vec<Value>> {
            match dns.remove(key) {
                None => Ok(Vec::new()),
                Some(Value::Array(list)) => Ok(list),
                Some(_) => Err(anyhow!("dns.{}: not a list", key)),
            }
        };
        let mut existing = list("servers", &mut out.dns)?;
        if existing
            .iter()
            .any(|s| s["tag"] == HOSTS || s["tag"] == SYSTEM_HOSTS)
        {
            return Err(anyhow!(
                "dns: a server is tagged {} or {}, which hosts take",
                HOSTS,
                SYSTEM_HOSTS
            ));
        }
        // Without a final server named, the first is: keep it so.
        if !out.dns.contains_key("final") {
            if let Some(tag) = existing.first().and_then(|s| s["tag"].as_str()) {
                out.dns.insert("final".into(), json!(tag));
            }
        }
        existing.extend(servers);
        let mut existing_rules = list("rules", &mut out.dns)?;
        rules.append(&mut existing_rules);
        out.dns.insert("servers".into(), Value::Array(existing));
        out.dns.insert("rules".into(), Value::Array(rules));
        Ok(())
    }
}
