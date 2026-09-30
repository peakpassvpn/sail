//! `network`, a sail extension, as Surge's `subnet` group: sends each
//! connection to the outbound of the first branch whose conditions the
//! network the host is on matches (`wifi_ssid`, `network_type`, …), or to
//! `default` when none does.
//!
//! The branch is taken for each connection from the network as it is at
//! the time, so the group follows a change of network with no timer; the
//! connections already open stay on the outbound they went through, where
//! Surge would move them.

use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::sync::RwLock;
use tracing::debug;

use super::members::{MemberKey, Members};
use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::*;
use crate::app::outbound::selector::{OutboundSelector, SelectedBy, Selection};
use crate::app::router::matcher::NetworkConditions;
use crate::app::SyncDnsClient;
use crate::config::model::{self, listable};
use crate::net::network::{Network, NetworkState};
use crate::net::{connect_datagram_outbound, connect_stream_outbound};
use crate::session::Session;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("network", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkGroupOptions {
    /// Tried in order: the first whose conditions the network matches
    /// takes the connection.
    branches: Vec<Branch>,
    /// Where connections go when no branch matches.
    default: String,
}

/// An outbound, and the network it is for: conditions as a routing
/// rule's, each of which must match, a list when any of its values does.
/// A condition on something not known of the network does not match.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Branch {
    outbound: String,
    #[serde(default, with = "listable")]
    wifi_ssid: Vec<String>,
    #[serde(default, with = "listable")]
    wifi_bssid: Vec<String>,
    /// `wifi`, `cellular`, `ethernet`, `other`.
    #[serde(default, with = "listable")]
    network_type: Vec<String>,
    #[serde(default)]
    network_is_expensive: bool,
    #[serde(default)]
    network_is_constrained: bool,
    #[serde(default, with = "listable")]
    wifi_ssid_regex: Vec<String>,
    /// Matched whatever the case.
    #[serde(default, with = "listable")]
    wifi_bssid_regex: Vec<String>,
    #[serde(default, with = "listable")]
    network_gateway: Vec<String>,
    /// Only off Wi-Fi.
    #[serde(default, with = "listable")]
    network_mcc_mnc: Vec<String>,
}

impl Branch {
    /// Its conditions, as a routing rule has them.
    fn rule(&self) -> model::Rule {
        model::Rule {
            wifi_ssid: self.wifi_ssid.clone(),
            wifi_bssid: self.wifi_bssid.clone(),
            network_type: self.network_type.clone(),
            network_is_expensive: self.network_is_expensive,
            network_is_constrained: self.network_is_constrained,
            wifi_ssid_regex: self.wifi_ssid_regex.clone(),
            wifi_bssid_regex: self.wifi_bssid_regex.clone(),
            network_gateway: self.network_gateway.clone(),
            network_mcc_mnc: self.network_mcc_mnc.clone(),
            ..Default::default()
        }
    }
}

/// The outbounds of the branches and the default, each once, in order.
fn outbounds(options: &NetworkGroupOptions) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for tag in options
        .branches
        .iter()
        .map(|b| &b.outbound)
        .chain([&options.default])
    {
        if !tags.contains(tag) {
            tags.push(tag.clone());
        }
    }
    tags
}

fn dependencies(tag: &str, options: &Options) -> Result<Vec<String>> {
    let options: NetworkGroupOptions = parse_options("outbound", tag, options)?;
    Ok(outbounds(&options))
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: NetworkGroupOptions = ctx.options()?;
    if options.branches.is_empty() {
        return Err(anyhow!(
            "[{}] outbound: branches: a network group needs some; without, name `default` itself",
            ctx.tag
        ));
    }
    let tags = outbounds(&options);
    let handlers = ctx.members(&tags)?;
    let at = |i: usize| -> usize {
        tags.iter()
            .position(|t| *t == options.branches[i].outbound)
            .expect("a branch's outbound is a member")
    };
    let branches = options
        .branches
        .iter()
        .enumerate()
        .map(|(i, branch)| {
            let path = format!("branches[{}]", i);
            let conditions = NetworkConditions::compile(&branch.rule(), &path)
                .map_err(|e| anyhow!("[{}] outbound: {}", ctx.tag, e))?;
            if conditions.is_empty() {
                return Err(anyhow!(
                    "[{}] outbound: {}: a branch needs conditions on the network; `default` takes the rest",
                    ctx.tag,
                    path
                ));
            }
            Ok((conditions, at(i)))
        })
        .collect::<Result<Vec<_>>>()?;
    let default = tags
        .iter()
        .position(|t| *t == options.default)
        .expect("the default is a member");
    let udp = handlers.iter().any(|h| h.datagram().is_ok());
    let group = Arc::new(Group {
        tag: ctx.tag.to_owned(),
        members: tags.iter().cloned().zip(handlers.iter().cloned()).collect(),
        branches,
        default,
        network: ctx.env.network.clone(),
        dns_client: ctx.dns_client.clone(),
    });

    // What the Clash API shows: the member the network calls for now.
    let now = {
        let group = Arc::downgrade(&group);
        Box::new(move || {
            group
                .upgrade()
                .map(|g| g.members[g.pick(&g.network.snapshot())].0.clone())
                .unwrap_or_default()
        })
    };
    let selector = OutboundSelector::new(
        ctx.tag.to_owned(),
        Members::outbounds(&tags, handlers),
        Arc::new(Selection::new(
            &options.default,
            MemberKey::outbound(&options.default),
        )),
        SelectedBy::State(now),
        None,
    );
    ctx.selectors
        .insert(ctx.tag.to_owned(), Arc::new(RwLock::new(selector)));

    let builder = HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(group.clone());
    // UDP when any member carries it: the member picked may not.
    Ok(match udp {
        true => builder.datagram_handler(group).build(),
        false => builder.build(),
    })
}

struct Group {
    tag: String,
    /// Each outbound of the branches and the default, by tag, once.
    members: Vec<(String, AnyOutboundHandler)>,
    /// Their conditions, and the member each goes to.
    branches: Vec<(NetworkConditions, usize)>,
    default: usize,
    network: Network,
    dns_client: SyncDnsClient,
}

impl Group {
    /// The member the network `state` calls for: the first branch's that
    /// it matches, or the default.
    fn pick(&self, state: &NetworkState) -> usize {
        self.branches
            .iter()
            .find(|(conditions, _)| conditions.matches(Some(state)))
            .map_or(self.default, |&(_, member)| member)
    }

    /// The member for a connection now, as the network is.
    fn member(&self, sess: &Session) -> &(String, AnyOutboundHandler) {
        let member = &self.members[self.pick(&self.network.snapshot())];
        debug!(
            "[{}] handles [{}:{}] to [{}]",
            self.tag, sess.network, sess.destination, member.0
        );
        member
    }
}

#[async_trait]
impl OutboundStreamHandler for Group {
    fn connect_addr(&self) -> OutboundConnect {
        // The member is picked, and dialled, per connection.
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let (name, a) = self.member(sess);
        let stream = connect_stream_outbound(sess, self.dns_client.clone(), a).await?;
        let stream = a.stream()?.handle(sess, None, stream).await?;
        sess.chain.push(name);
        Ok(stream)
    }
}

#[async_trait]
impl OutboundDatagramHandler for Group {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let (name, a) = self.member(sess);
        let transport = connect_datagram_outbound(sess, self.dns_client.clone(), a).await?;
        let datagram = a.datagram()?.handle(sess, transport).await?;
        sess.chain.push(name);
        Ok(datagram)
    }
}

#[cfg(test)]
mod tests {
    use crate::app::dns::DnsClient;
    use crate::app::outbound::manager::OutboundManager;
    use crate::net::network::NetworkState;
    use crate::runtime::RuntimeEnv;

    fn manager(group: serde_json::Value, env: &RuntimeEnv) -> anyhow::Result<OutboundManager> {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "outbounds": [
                group,
                { "type": "direct", "tag": "a" },
                { "type": "direct", "tag": "b" },
                { "type": "direct", "tag": "c" }
            ] })
            .to_string(),
        )?;
        let dns = DnsClient::new(&config.dns, Default::default(), env)?.into_shared();
        OutboundManager::new(&config.outbounds, &Default::default(), env, dns)
    }

    fn scene() -> serde_json::Value {
        serde_json::json!({ "type": "network", "tag": "scene",
            "branches": [
                { "wifi_ssid": "Home", "outbound": "a" },
                { "network_type": ["wifi", "ethernet"], "outbound": "b" },
                { "network_type": "cellular", "network_is_expensive": true, "outbound": "a" }
            ],
            "default": "c" })
    }

    fn push(env: &RuntimeEnv, json: serde_json::Value) {
        env.network
            .push(NetworkState::from_json(&json.to_string()).unwrap());
    }

    /// The first branch the network matches, in order, else the default;
    /// asked again as the network changes.
    #[tokio::test]
    async fn the_first_branch_the_network_matches_is_taken() {
        let env = RuntimeEnv::default();
        let manager = manager(scene(), &env).unwrap();
        assert!(manager.needs_network());
        let selector = manager.get_selector("scene").unwrap();
        let now = || async { selector.read().await.get_selected_tag() };
        assert_eq!(selector.read().await.get_available_tags(), ["a", "b", "c"]);
        assert!(!selector.read().await.is_selectable());

        assert_eq!(now().await, "c");
        push(&env, serde_json::json!({ "type": "wifi", "ssid": "Home" }));
        assert_eq!(now().await, "a");
        push(&env, serde_json::json!({ "type": "wifi", "ssid": "Cafe" }));
        assert_eq!(now().await, "b");
        push(&env, serde_json::json!({ "type": "cellular" }));
        assert_eq!(now().await, "c");
        push(
            &env,
            serde_json::json!({ "type": "cellular", "expensive": true }),
        );
        assert_eq!(now().await, "a");
        assert!(selector.write().await.set_selected("b").is_err());
    }

    #[test]
    fn only_a_network_group_needs_the_network() {
        let env = RuntimeEnv::default();
        let manager = manager(serde_json::json!({ "type": "direct", "tag": "d" }), &env).unwrap();
        assert!(!manager.needs_network());
    }

    /// UDP when a member carries it.
    #[test]
    fn udp_is_the_members() {
        let env = RuntimeEnv::default();
        let manager = manager(scene(), &env).unwrap();
        assert!(manager.get("scene").unwrap().datagram().is_ok());
    }

    #[test]
    fn mistakes_name_the_branch_and_the_field() {
        let env = RuntimeEnv::default();
        for (group, message) in [
            (
                serde_json::json!({ "type": "network", "tag": "g",
                    "branches": [{ "outbound": "a" }], "default": "c" }),
                "[g] outbound: branches[0]: a branch needs conditions on the network",
            ),
            (
                serde_json::json!({ "type": "network", "tag": "g",
                    "branches": [
                        { "wifi_ssid": "Home", "outbound": "a" },
                        { "wifi_bssid": "nope", "outbound": "b" }
                    ], "default": "c" }),
                "[g] outbound: branches[1].wifi_bssid: \"nope\" is no MAC address",
            ),
            (
                serde_json::json!({ "type": "network", "tag": "g",
                    "branches": [{ "domain": "a.example", "outbound": "a" }], "default": "c" }),
                "[g] outbound: branches[0].domain: unknown field `domain`",
            ),
            (
                serde_json::json!({ "type": "network", "tag": "g",
                    "branches": [{ "wifi_ssid": "Home", "outbound": "a" }] }),
                "[g] outbound: missing field `default`",
            ),
            (
                serde_json::json!({ "type": "network", "tag": "g",
                    "branches": [], "default": "c" }),
                "[g] outbound: branches: a network group needs some",
            ),
        ] {
            let err = manager(group.clone(), &env).err().unwrap().to_string();
            assert!(err.starts_with(message), "{}: {}", group, err);
        }
        let err = manager(
            serde_json::json!({ "type": "network", "tag": "g",
                "branches": [{ "wifi_ssid": "Home", "outbound": "x" }], "default": "c" }),
            &env,
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("[x]"), "{}", err);
    }
}
