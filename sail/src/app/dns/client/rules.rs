//! The DNS rules: which server a query goes to, the responses `evaluate`
//! rules keep for the rules after them, and how each query is sent.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{anyhow, Result};
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::{RData, RecordType};
use tracing::debug;

use super::server::Kind;
use super::{DnsClient, LookupContext, QueryOptions, Rule, RuleAction, Subnet};
use crate::app::router::matcher::Facts;
use crate::config::model::{DnsRuleAction, DnsStrategy, Prefix, ResponseRef};
use crate::session::{Session, SocksAddr};

/// What the rules make of a query.
pub(super) enum Walked {
    /// A server's response, or one an `evaluate` rule kept.
    Response(Message),
    /// A rule rejects it.
    Refused,
}

/// Where the rules would send a query, as far as can be told before it is
/// sent: for finding what resolving needs.
pub(super) struct Reach {
    pub servers: Vec<String>,
}

/// How the first rule that matches a query without its response sets the
/// families of a lookup.
enum RuleStrategy {
    /// It sends the query, with a strategy of its own or none.
    Sent(Option<DnsStrategy>),
    Rejected,
}

impl DnsClient {
    pub(super) fn load_rules(
        dns: &crate::config::Dns,
        env: &crate::runtime::RuntimeEnv,
        rule_sets: &crate::app::router::rule_set::RuleSets,
    ) -> Result<Vec<Rule>> {
        let mut readers = crate::app::router::matcher::Readers::new();
        let mut rules = Vec::new();
        for (i, rule) in dns.rules.iter().enumerate() {
            let matcher = crate::app::router::matcher::Matcher::at(
                &rule.conditions(),
                &format!("dns.rules[{}]", i),
                &mut readers,
                env,
                rule_sets,
            )?;
            // The servers are checked with the model.
            let server = rule.server.clone().unwrap_or_default();
            let options = QueryOptions::of(rule);
            let action = match rule.action.unwrap_or_default() {
                DnsRuleAction::Route => RuleAction::Route {
                    server,
                    strategy: rule.strategy,
                    options,
                },
                DnsRuleAction::Evaluate => RuleAction::Evaluate {
                    server,
                    tag: rule.tag.clone(),
                    options,
                },
                DnsRuleAction::Respond => RuleAction::Respond,
                DnsRuleAction::RouteOptions => RuleAction::RouteOptions(options),
                DnsRuleAction::Reject => RuleAction::Reject,
            };
            rules.push(Rule {
                matcher,
                outbounds: rule.outbound.clone(),
                response: rule.match_response.clone(),
                invert: rule.invert,
                action,
            });
        }
        Ok(rules)
    }

    /// The facts of a query of type `ty` for `host`, made for `ctx`.
    fn facts(host: &str, ty: RecordType, ctx: &LookupContext, response: Option<&Message>) -> Facts {
        let sess = Session {
            destination: SocksAddr::Domain(host.to_string(), 0),
            inbound_tag: ctx.inbound.clone().unwrap_or_default(),
            user: ctx.user.clone(),
            ..Default::default()
        };
        let facts = match response {
            Some(response) => Facts::new(&sess, &addresses(response))
                .with_rcode(u16::from(response.response_code())),
            None => Facts::new(&sess, &[]),
        };
        facts.with_query_type(ty.into())
    }

    /// Whether the rule is for the outbound `ctx` dials for.
    fn for_outbound(rule: &Rule, ctx: &LookupContext) -> bool {
        rule.outbounds.is_empty()
            || ctx
                .outbound
                .as_ref()
                .is_some_and(|o| rule.outbounds.contains(o))
    }

    fn is_fake_ip(&self, tag: &str) -> bool {
        self.servers
            .get(tag)
            .is_some_and(|s| matches!(s.kind, Kind::FakeIp(_)))
    }

    /// Sends `request` where the rules say, as sing-box walks them: in
    /// order, each `evaluate` rule that matches asking its server and
    /// keeping the response for the rules after it, until one answers or
    /// rejects; `dns.final` takes the rest. A lookup of the instance's own
    /// (`fake_ip` false) passes over the rules that send it to the fakeip
    /// server, whose addresses are for clients alone.
    pub(super) async fn walk(
        &self,
        request: &Message,
        ctx: &LookupContext,
        fake_ip: bool,
    ) -> Result<Walked> {
        let query = request
            .queries()
            .first()
            .ok_or_else(|| anyhow!("a query without a question"))?;
        let ty = query.query_type();
        let host = query.name().to_utf8();
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        // The last response without a tag, and the tagged ones; `None` for
        // a server that did not answer.
        let mut latest: Option<Option<Message>> = None;
        let mut tagged: HashMap<&str, Option<Message>> = HashMap::new();
        let mut options = QueryOptions::default();
        for (i, rule) in self.rules.iter().enumerate() {
            if !Self::for_outbound(rule, ctx) {
                continue;
            }
            let response = match &rule.response {
                None => None,
                Some(ResponseRef::Latest) => Some(latest.as_ref().and_then(Option::as_ref)),
                Some(ResponseRef::Tag(tag)) => {
                    Some(tagged.get(tag.as_str()).and_then(Option::as_ref))
                }
            };
            let matched = match response {
                // Without its response, a rule matches only inverted, as
                // in sing-box.
                Some(None) => rule.invert,
                Some(Some(response)) => {
                    rule.matcher
                        .matches(&Self::facts(&host, ty, ctx, Some(response)))
                }
                None => rule.matcher.matches(&Self::facts(&host, ty, ctx, None)),
            };
            if !matched {
                continue;
            }
            match &rule.action {
                RuleAction::RouteOptions(set) => {
                    debug!("dns rule {} matches {} {}: route options", i, host, ty);
                    options = options.with(set);
                }
                RuleAction::Evaluate {
                    server,
                    tag,
                    options: own,
                } => {
                    debug!(
                        "dns rule {} matches {} {}: evaluate [{}]",
                        i, host, ty, server
                    );
                    let response = match self.resolve(server, request, &options.with(own)).await {
                        Ok(response) => Some(response),
                        Err(e) => {
                            debug!("{} {}: evaluate [{}]: {}", host, ty, server, e);
                            None
                        }
                    };
                    match tag {
                        None => latest = Some(response),
                        Some(tag) => {
                            tagged.insert(tag, response);
                        }
                    }
                }
                RuleAction::Respond => {
                    debug!("dns rule {} matches {} {}: respond", i, host, ty);
                    let response = match &rule.response {
                        Some(ResponseRef::Tag(tag)) => tagged.get(tag.as_str()).cloned(),
                        _ => latest.clone(),
                    };
                    return match response.flatten() {
                        Some(response) => Ok(Walked::Response(response)),
                        None => Err(anyhow!(
                            "{} {}: dns rule {} responds, and there is no evaluated response",
                            host,
                            ty,
                            i
                        )),
                    };
                }
                RuleAction::Route {
                    server,
                    options: own,
                    ..
                } => {
                    if !fake_ip && self.is_fake_ip(server) {
                        continue;
                    }
                    debug!("dns rule {} matches {} {}: [{}]", i, host, ty, server);
                    return self
                        .resolve(server, request, &options.with(own))
                        .await
                        .map(Walked::Response);
                }
                RuleAction::Reject => {
                    debug!("dns rule {} matches {} {}: reject", i, host, ty);
                    return Ok(Walked::Refused);
                }
            }
        }
        self.resolve(&self.final_server, request, &options)
            .await
            .map(Walked::Response)
    }

    /// The families a lookup of `host` for `ctx` asks for: what `ctx`
    /// says, or the `strategy` of the rule that sends the A query (the AAAA
    /// one when it rejects that), or `dns.strategy`. Rules that set one
    /// match no evaluated response, as the model checks.
    pub(super) fn lookup_strategy(&self, host: &str, ctx: &LookupContext) -> DnsStrategy {
        if let Some(strategy) = ctx.strategy {
            return strategy;
        }
        if !self.rules_set_strategy {
            return self.strategy;
        }
        let of = |ty| self.rule_strategy(host, ty, ctx);
        match (of(RecordType::A), of(RecordType::AAAA)) {
            (RuleStrategy::Sent(strategy), _)
            | (RuleStrategy::Rejected, RuleStrategy::Sent(strategy)) => {
                strategy.unwrap_or(self.strategy)
            }
            (RuleStrategy::Rejected, RuleStrategy::Rejected) => self.strategy,
        }
    }

    /// The families a client's query of `ty` is answered for: a family the
    /// strategy leaves out has no records.
    pub(super) fn query_strategy(
        &self,
        host: &str,
        ty: RecordType,
        ctx: &LookupContext,
    ) -> DnsStrategy {
        if let Some(strategy) = ctx.strategy {
            return strategy;
        }
        match self.rules_set_strategy {
            true => match self.rule_strategy(host, ty, ctx) {
                RuleStrategy::Sent(Some(strategy)) => strategy,
                _ => self.strategy,
            },
            false => self.strategy,
        }
    }

    fn rule_strategy(&self, host: &str, ty: RecordType, ctx: &LookupContext) -> RuleStrategy {
        let facts = Self::facts(host, ty, ctx, None);
        for rule in &self.rules {
            if rule.response.is_some()
                || !Self::for_outbound(rule, ctx)
                || !rule.matcher.matches(&facts)
            {
                continue;
            }
            match &rule.action {
                RuleAction::Route {
                    server, strategy, ..
                } if !self.is_fake_ip(server) => return RuleStrategy::Sent(*strategy),
                RuleAction::Reject => return RuleStrategy::Rejected,
                _ => {}
            }
        }
        RuleStrategy::Sent(None)
    }

    /// The servers a lookup of `host` of type `ty` for `ctx` may ask:
    /// those of the `evaluate` rules that match it, and of the rules that
    /// may send it, up to the first that surely does.
    pub(super) fn reach(&self, host: &str, ty: RecordType, ctx: &LookupContext) -> Reach {
        let facts = Self::facts(host, ty, ctx, None);
        let mut servers = Vec::new();
        for rule in &self.rules {
            if !Self::for_outbound(rule, ctx) {
                continue;
            }
            // A rule on a response may match it or not.
            let surely = rule.response.is_none();
            if surely && !rule.matcher.matches(&facts) {
                continue;
            }
            match &rule.action {
                RuleAction::Evaluate { server, .. } => servers.push(server.clone()),
                RuleAction::Route { server, .. } if !self.is_fake_ip(server) => {
                    servers.push(server.clone());
                    if surely {
                        return Reach { servers };
                    }
                }
                RuleAction::Respond | RuleAction::Reject if surely => {
                    return Reach { servers };
                }
                _ => {}
            }
        }
        servers.push(self.final_server.clone());
        Reach { servers }
    }

    /// Asks the server tagged `tag` `request`, sent as `options` says: its
    /// client subnet, its time, its TTLs. An answer comes from the cache
    /// while it lasts, but a fake IP's, whose address its store may have
    /// handed to another domain by then.
    pub(super) async fn resolve(
        &self,
        tag: &str,
        request: &Message,
        options: &QueryOptions,
    ) -> Result<Message> {
        let server = self.server(tag)?.clone();
        let mut request = request.clone();
        match options
            .client_subnet
            .or(self.client_subnet.map(Subnet::Set))
        {
            Some(Subnet::Set(prefix)) => set_client_subnet(&mut request, prefix),
            Some(Subnet::Remove) => remove_client_subnet(&mut request),
            None => {}
        }
        let cached = !options.disable_cache && !matches!(server.kind, Kind::FakeIp(_));
        let key = request.queries().first().map(|q| {
            let name = q.name().to_utf8();
            (
                tag.to_string(),
                name.trim_end_matches('.').to_ascii_lowercase(),
                u16::from(q.query_type()),
                client_subnet(&request),
            )
        });
        if let (true, Some(key)) = (cached, &key) {
            if let Some(answer) = self.cached_answer(key, request.id()) {
                return Ok(answer);
            }
        }
        let timeout = options.timeout.unwrap_or(self.timeout);
        let mut response = match self.query(&server, &request, timeout).await? {
            super::Answer::Message(message) => message,
            super::Answer::Ips(ips) => {
                Self::reply(&request, &ips, super::LOCAL_TTL.as_secs() as u32)
            }
        };
        response.set_id(request.id());
        if let Some(ttl) = options.rewrite_ttl {
            for record in response.answers_mut() {
                record.set_ttl(ttl);
            }
            for record in response.name_servers_mut() {
                record.set_ttl(ttl);
            }
        }
        let keeps = matches!(
            response.response_code(),
            ResponseCode::NoError | ResponseCode::NXDomain
        );
        if let (true, true, Some(key)) = (cached, keeps, key) {
            self.cache_answer(key, &response);
        }
        Ok(response)
    }
}

/// The addresses a response carries.
pub(super) fn addresses(response: &Message) -> Vec<IpAddr> {
    response
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            Some(RData::A(ip)) => Some(IpAddr::V4(**ip)),
            Some(RData::AAAA(ip)) => Some(IpAddr::V6(**ip)),
            _ => None,
        })
        .collect()
}

/// The client subnet `request` carries.
pub(super) fn client_subnet(request: &Message) -> Option<Prefix> {
    let option = request.extensions().as_ref()?.option(EdnsCode::Subnet)?;
    let EdnsOption::Subnet(subnet) = option else {
        return None;
    };
    // FAMILY, SOURCE PREFIX-LENGTH, SCOPE PREFIX-LENGTH, ADDRESS.
    let bytes = Vec::<u8>::try_from(subnet).ok()?;
    let (head, address) = bytes.split_at_checked(4)?;
    let len = head[2];
    let addr = match u16::from_be_bytes([head[0], head[1]]) {
        1 => {
            let mut octets = [0u8; 4];
            octets.get_mut(..address.len())?.copy_from_slice(address);
            IpAddr::from(octets)
        }
        2 => {
            let mut octets = [0u8; 16];
            octets.get_mut(..address.len())?.copy_from_slice(address);
            IpAddr::from(octets)
        }
        _ => return None,
    };
    Some(Prefix { addr, len })
}

/// Makes `request` carry `prefix` as its client subnet, in place of any it
/// has; the address's bits past the prefix are cleared, as RFC 7871 wants.
fn set_client_subnet(request: &mut Message, prefix: Prefix) {
    let addr = match prefix.addr {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - prefix.len as u32).unwrap_or(0);
            IpAddr::from((u32::from(v4) & mask).to_be_bytes())
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - prefix.len as u32).unwrap_or(0);
            IpAddr::from((u128::from(v6) & mask).to_be_bytes())
        }
    };
    let edns = request.extensions_mut().get_or_insert_with(|| {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns
    });
    edns.options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::new(addr, prefix.len, 0)));
}

fn remove_client_subnet(request: &mut Message) {
    if let Some(edns) = request.extensions_mut() {
        edns.options_mut().remove(EdnsCode::Subnet);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_subnet_is_set_masked_and_read_back() {
        let mut request = Message::new();
        let prefix: Prefix = "223.5.5.77/24".parse().unwrap();
        set_client_subnet(&mut request, prefix);
        let read = client_subnet(&Message::from_vec(&request.to_vec().unwrap()).unwrap());
        assert_eq!(read, Some("223.5.5.0/24".parse().unwrap()));

        let prefix: Prefix = "2001:db8:1:2::5/56".parse().unwrap();
        set_client_subnet(&mut request, prefix);
        let read = client_subnet(&Message::from_vec(&request.to_vec().unwrap()).unwrap());
        assert_eq!(read, Some("2001:db8:1::/56".parse().unwrap()));

        remove_client_subnet(&mut request);
        assert_eq!(client_subnet(&request), None);
    }
}
