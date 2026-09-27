use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use futures::future::select_ok;
use hickory_proto::{
    op::{
        header::MessageType, op_code::OpCode, query::Query, response_code::ResponseCode, Message,
    },
    rr::{record_data::RData, record_type::RecordType, resource::Record, Name},
};
use lru::LruCache;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::timeout;
use tracing::{debug, trace, Instrument};

use crate::{
    adapter::*, app::dispatcher::Dispatcher, config::model::DnsStrategy, net::*, session::*,
};
include!("client/types.rs");

mod fakeip;
mod server;
mod upstream;

pub use fakeip::FakeIp;

use server::{Address, Dialer, Kind, Server};

/// How long the system resolver's and a hosts server's answers are kept:
/// they carry no TTL.
const LOCAL_TTL: Duration = Duration::from_secs(60);
/// The TTL of a fake IP's answer: sing-box's.
const FAKE_IP_TTL: u32 = 600;
/// The TTL of a hosts server's answer: sing-box's.
const HOSTS_TTL: u32 = 600;

impl DnsClient {
    pub fn new(
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialOptions>,
        env: &crate::runtime::RuntimeEnv,
    ) -> Result<Self> {
        Self::with_rule_sets(dns, dial, env, &Default::default())
    }

    /// A client whose rules can name the rule-sets of `rule_sets`.
    pub(crate) fn with_rule_sets(
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialOptions>,
        env: &crate::runtime::RuntimeEnv,
        rule_sets: &crate::app::router::rule_set::RuleSets,
    ) -> Result<Self> {
        Self::build(dns, dial, env, rule_sets, None)
    }

    fn build(
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialOptions>,
        env: &crate::runtime::RuntimeEnv,
        rule_sets: &crate::app::router::rule_set::RuleSets,
        fake_ips: Option<&Arc<fakeip::FakeIpStore>>,
    ) -> Result<Self> {
        let tuning = env.options.dns.clone();
        let local = crate::config::model::DnsServer {
            kind: "local".into(),
            tag: "local".into(),
            options: Default::default(),
        };
        let configs = if dns.servers.is_empty() {
            std::slice::from_ref(&local)
        } else {
            &dns.servers[..]
        };
        let mut servers = HashMap::new();
        let mut fake_ip_store = None;
        for config in configs {
            let server = Server::new(config, &dial, env, &tuning, fake_ips)?;
            if let Kind::FakeIp(store) = &server.kind {
                if fake_ip_store.replace(store.clone()).is_some() {
                    return Err(anyhow!(
                        "dns.servers[{}]: one fakeip server is all there can be",
                        config.tag
                    ));
                }
            }
            debug!("dns server {}", server);
            servers.insert(config.tag.clone(), Arc::new(server));
        }
        server::check(&servers)?;
        let final_server = dns
            .final_server
            .clone()
            .unwrap_or_else(|| configs[0].tag.clone());
        let rules = Self::load_rules(dns, env, rule_sets)?;
        let capacity = NonZeroUsize::new(dns.cache_capacity())
            .ok_or_else(|| anyhow!("dns.cache_capacity: must be at least 1"))?;
        Ok(Self {
            dispatcher: Default::default(),
            servers,
            rules,
            final_server,
            ipv4_cache: Arc::new(TokioMutex::new(LruCache::new(capacity))),
            ipv6_cache: Arc::new(TokioMutex::new(LruCache::new(capacity))),
            ech_cache: Arc::new(TokioMutex::new(LruCache::new(capacity))),
            ech_query_locks: Arc::new(TokioMutex::new(HashMap::new())),
            answers: Arc::new(std::sync::Mutex::new(LruCache::new(capacity))),
            fake_ips: fake_ip_store,
            tuning,
            strategy: dns.strategy,
            timeout: dns.timeout(),
            reverse_mapping: dns.reverse_mapping,
        })
    }

    /// Shares the client between its users, who see it replaced whole on
    /// reload.
    pub fn into_shared(self) -> crate::app::SyncDnsClient {
        Arc::new(arc_swap::ArcSwap::from_pointee(self))
    }

    /// Servers with a `detour` reach it through `dispatcher`, once it
    /// exists.
    pub fn set_dispatcher(&self, dispatcher: Weak<Dispatcher>) {
        let _ = self.dispatcher.set(dispatcher);
    }

    /// A client for `dns`, to replace this one: it starts with empty caches,
    /// and reaches detours as this one does.
    pub(crate) fn reloaded(
        &self,
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialOptions>,
        env: &crate::runtime::RuntimeEnv,
        rule_sets: &crate::app::router::rule_set::RuleSets,
    ) -> Result<Self> {
        // The fake IPs handed out stay theirs, as long as the ranges do.
        let mut client = Self::build(dns, dial, env, rule_sets, self.fake_ips.as_ref())?;
        client.dispatcher = self.dispatcher.clone();
        Ok(client)
    }

    /// Whether `dns.reverse_mapping` is on.
    pub fn reverse_mapping(&self) -> bool {
        self.reverse_mapping
    }

    fn load_rules(
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
            let action = match rule.action.unwrap_or_default() {
                crate::config::model::DnsRuleAction::Route => RuleAction::Route {
                    // Checked with the model.
                    server: rule.server.clone().unwrap_or_default(),
                    strategy: rule.strategy,
                },
                crate::config::model::DnsRuleAction::Reject => RuleAction::Reject,
            };
            rules.push(Rule {
                matcher,
                outbounds: rule.outbound.clone(),
                action,
            });
        }
        Ok(rules)
    }

    /// Where a query of type `ty` for `host` goes: the first rule that
    /// matches it decides, and `final` takes the rest.
    fn pick(&self, host: &str, ty: RecordType, ctx: &LookupContext) -> Pick {
        let sess = Session {
            destination: SocksAddr::Domain(host.to_string(), 0),
            inbound_tag: ctx.inbound.clone().unwrap_or_default(),
            user: ctx.user.clone(),
            ..Default::default()
        };
        let facts = crate::app::router::matcher::Facts::new(&sess, &[]).with_query_type(ty.into());
        for (i, rule) in self.rules.iter().enumerate() {
            if !rule.outbounds.is_empty()
                && !ctx
                    .outbound
                    .as_ref()
                    .is_some_and(|o| rule.outbounds.contains(o))
            {
                continue;
            }
            if !rule.matcher.matches(&facts) {
                continue;
            }
            debug!("dns rule {} matches {} {}", i, host, ty);
            return match &rule.action {
                RuleAction::Route { server, strategy } => Pick::Server(
                    server.clone(),
                    ctx.strategy.or(*strategy).unwrap_or(self.strategy),
                ),
                RuleAction::Reject => Pick::Reject,
            };
        }
        Pick::Server(
            self.final_server.clone(),
            ctx.strategy.unwrap_or(self.strategy),
        )
    }

    /// Fails when resolving a name needs what the resolving itself needs:
    /// a server whose `detour` dials a server name that resolves, through
    /// its `domain_resolver`, `route.default_domain_resolver` or the DNS
    /// rules, back at that server; outbounds' own `detour` and a group's
    /// members are followed too. Such a query could only time out.
    pub fn check_loops(
        &self,
        outbounds: &[crate::config::Outbound],
        default_resolver: Option<&crate::config::model::DomainResolver>,
    ) -> Result<()> {
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        enum Node {
            Dns(String),
            Outbound(String),
        }
        impl std::fmt::Display for Node {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Node::Dns(tag) => write!(f, "dns server [{}]", tag),
                    Node::Outbound(tag) => write!(f, "outbound [{}]", tag),
                }
            }
        }
        let mut edges: HashMap<Node, Vec<Node>> = HashMap::new();
        for server in self.servers.values() {
            let node = Node::Dns(server.tag.clone());
            let next = edges.entry(node).or_default();
            next.extend(server.needs().into_iter().map(|t| Node::Dns(t.to_string())));
            let dialer = match &server.kind {
                Kind::Udp { dialer, .. } | Kind::Tcp { dialer, .. } => Some(dialer),
                Kind::Upstream(u) => Some(&u.dialer),
                _ => None,
            };
            if let Some(detour) = dialer.and_then(|d| d.detour.as_ref()) {
                next.push(Node::Outbound(detour.clone()));
            }
        }
        for outbound in outbounds {
            let node = Node::Outbound(outbound.tag.clone());
            let next = edges.entry(node).or_default();
            let options = &outbound.options;
            if let Some(members) = options.get("outbounds").and_then(|v| v.as_array()) {
                next.extend(
                    members
                        .iter()
                        .filter_map(|m| m.as_str())
                        .map(|m| Node::Outbound(m.to_string())),
                );
            }
            if let Some(detour) = options.get("detour").and_then(|v| v.as_str()) {
                // Its server is dialled by the detour, which resolves it.
                next.push(Node::Outbound(detour.to_string()));
                continue;
            }
            let Some(host) = options.get("server").and_then(|v| v.as_str()) else {
                continue;
            };
            if host.parse::<IpAddr>().is_ok() {
                continue;
            }
            let resolver = options
                .get("domain_resolver")
                .and_then(|v| {
                    <crate::config::model::DomainResolver as serde::Deserialize>::deserialize(v)
                        .ok()
                })
                .or_else(|| default_resolver.cloned());
            let servers = match resolver {
                Some(resolver) => vec![resolver.server],
                None => {
                    let ctx = LookupContext {
                        outbound: Some(outbound.tag.clone()),
                        ..Default::default()
                    };
                    [RecordType::A, RecordType::AAAA]
                        .into_iter()
                        .filter_map(|ty| match self.pick(host, ty, &ctx) {
                            Pick::Server(tag, _) => Some(tag),
                            Pick::Reject => None,
                        })
                        .collect()
                }
            };
            next.extend(servers.into_iter().map(Node::Dns));
        }

        fn visit(
            edges: &HashMap<Node, Vec<Node>>,
            node: &Node,
            path: &mut Vec<Node>,
            done: &mut std::collections::HashSet<Node>,
        ) -> Result<()> {
            if done.contains(node) {
                return Ok(());
            }
            if let Some(i) = path.iter().position(|n| n == node) {
                let cycle: Vec<String> = path[i..]
                    .iter()
                    .chain(std::iter::once(node))
                    .map(|n| n.to_string())
                    .collect();
                // A loop among DNS servers alone was reported when they
                // were built; this one goes through an outbound.
                return Err(anyhow!(
                    "resolving needs itself: {}; set a domain_resolver that does not \
                     go through it",
                    cycle.join(" -> ")
                ));
            }
            path.push(node.clone());
            for next in edges.get(node).into_iter().flatten() {
                visit(edges, next, path, done)?;
            }
            path.pop();
            done.insert(node.clone());
            Ok(())
        }
        let mut nodes: Vec<&Node> = edges.keys().collect();
        nodes.sort();
        let mut done = std::collections::HashSet::new();
        for node in nodes {
            visit(&edges, node, &mut Vec::new(), &mut done)?;
        }
        Ok(())
    }

    fn server(&self, tag: &str) -> Result<&Arc<Server>> {
        self.servers
            .get(tag)
            .ok_or_else(|| anyhow!("dns server [{}] does not exist", tag))
    }

    // -- Reaching servers ------------------------------------------------

    /// Where a server is: its address, or what its resolver says its domain
    /// resolves to.
    async fn server_addr(&self, address: &Address) -> Result<SocketAddr> {
        if let Some(addr) = address.socket_addr() {
            return Ok(addr);
        }
        // A domain has a resolver: the servers were checked for that.
        let resolver = address
            .resolver
            .as_ref()
            .ok_or_else(|| anyhow!("no resolver for {}", address.host))?;
        let ips = self
            .lookup_with(
                &resolver.server,
                &address.host,
                resolver.strategy.unwrap_or(self.strategy),
            )
            .await
            .map_err(|e| anyhow!("resolving {}: {}", address.host, e))?;
        let ip = ips
            .first()
            .ok_or_else(|| anyhow!("{} resolves to no address", address.host))?;
        Ok(SocketAddr::new(*ip, address.port))
    }

    /// The session a detour carries a server's connection in.
    fn detour_session(network: Network, addr: SocketAddr, detour: &str) -> Session {
        let source = match addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        Session {
            network,
            source,
            destination: SocksAddr::from(addr),
            // Keeps a TLS detour from asking the DNS for ECH configs, which
            // could come back here.
            inbound_tag: "dnsclient".to_string(),
            outbound_tag: detour.to_string(),
            ..Default::default()
        }
    }

    fn dispatcher(&self) -> Result<Arc<Dispatcher>> {
        self.dispatcher
            .get()
            .ok_or_else(|| anyhow!("no dispatcher"))?
            .upgrade()
            .ok_or_else(|| anyhow!("dispatcher is gone"))
    }

    /// A TCP connection to `addr`, as the server's dialer makes them.
    async fn dial_stream(&self, dialer: &Dialer, addr: SocketAddr) -> Result<AnyStream> {
        match &dialer.detour {
            None => Ok(Box::new(crate::net::tcp_connect(addr, &dialer.dial).await?)),
            Some(detour) => {
                let sess = Self::detour_session(Network::Tcp, addr, detour);
                self.dispatcher()?
                    .stream_via(detour, sess)
                    .await
                    .map_err(|e| anyhow!("through [{}]: {}", detour, e))
            }
        }
    }

    /// Datagrams to `addr`, as the server's dialer sends them.
    async fn dial_datagram(
        &self,
        dialer: &Dialer,
        addr: SocketAddr,
    ) -> Result<AnyOutboundDatagram> {
        match &dialer.detour {
            None => {
                let socket = crate::net::new_udp_socket(&addr, &dialer.dial).await?;
                Ok(Box::new(StdOutboundDatagram::new(socket)))
            }
            Some(detour) => {
                let sess = Self::detour_session(Network::Udp, addr, detour);
                let span = sess.span();
                self.dispatcher()?
                    .datagram_via(detour, sess)
                    .instrument(span)
                    .await
                    .map_err(|e| anyhow!("through [{}]: {}", detour, e))
            }
        }
    }

    // -- Asking servers --------------------------------------------------

    /// Asks `server` `request`, within the query's time; a smart_select
    /// asks its members, as they have fared.
    #[async_recursion]
    async fn query(&self, server: &Server, request: &Message) -> Result<Answer> {
        if let Kind::SmartSelect { members, state } = &server.kind {
            return self.query_selected(members, state, request).await;
        }
        match timeout(self.timeout, self.ask(server, request)).await {
            Ok(res) => res,
            Err(_) => Err(anyhow!("{} {}: timeout", server, Self::question(request))),
        }
    }

    /// The question of a query, as logs name it.
    fn question(request: &Message) -> String {
        request
            .queries()
            .first()
            .map(|q| format!("{} {}", q.name(), q.query_type()))
            .unwrap_or_default()
    }

    /// Asks the member that fares best, then the others, as many at once
    /// as `fallback_concurrency` says, as they fare.
    async fn query_selected(
        &self,
        members: &[String],
        state: &std::sync::Mutex<ServerSelectorState>,
        request: &Message,
    ) -> Result<Answer> {
        let lock = || state.lock().unwrap_or_else(|e| e.into_inner());
        let ask = |idx: usize| {
            let tag = &members[idx];
            async move {
                let server = self.server(tag)?;
                let start = tokio::time::Instant::now();
                match self.query(server, request).await {
                    Ok(answer) => {
                        lock().mark_success(tag, start.elapsed());
                        Ok((idx, answer))
                    }
                    Err(e) => {
                        let is_timeout = e.to_string().contains("timeout");
                        lock().mark_failure(tag, is_timeout);
                        debug!("{} failed with [{}]: {}", Self::question(request), tag, e);
                        Err(anyhow!("[{}]: {}", tag, e))
                    }
                }
            }
        };

        let preferred = lock().select_primary_index(members);
        let mut errors = Vec::new();
        match ask(preferred).await {
            Ok((_, answer)) => return Ok(answer),
            Err(e) => errors.push(e.to_string()),
        }
        let fallback = lock().fallback_indices(members, preferred);
        for batch in fallback.chunks(self.tuning.fallback_concurrency.max(1)) {
            let tasks = batch.iter().map(|idx| Box::pin(ask(*idx)));
            match select_ok(tasks).await {
                Ok(((idx, answer), _)) => {
                    lock().set_primary(&members[idx]);
                    return Ok(answer);
                }
                Err(e) => errors.push(e.to_string()),
            }
        }
        Err(anyhow!("all dns queries failed: {}", errors.join("; ")))
    }

    /// Asks one server that is not a smart_select.
    async fn ask(&self, server: &Server, request: &Message) -> Result<Answer> {
        let query = request
            .queries()
            .first()
            .ok_or_else(|| anyhow!("a query without a question"))?;
        let (name, ty) = (query.name(), query.query_type());
        let host = name.to_utf8();
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let host = host.as_str();
        match &server.kind {
            Kind::Local => {
                let family = match ty {
                    RecordType::A => IpAddr::is_ipv4,
                    RecordType::AAAA => IpAddr::is_ipv6,
                    _ => return Err(anyhow!("the system resolver answers no {} query", ty)),
                };
                let addr = format!("{}:0", host);
                let ips = tokio::task::spawn_blocking(move || {
                    use std::net::ToSocketAddrs;
                    addr.to_socket_addrs()
                        .map(|iter| iter.map(|x| x.ip()).collect::<Vec<_>>())
                })
                .await
                .map_err(|e| anyhow!("spawn blocking failed: {}", e))?
                .map_err(|e| anyhow!("system resolver failed: {}", e))?;
                Ok(Answer::Ips(ips.into_iter().filter(family).collect()))
            }
            // As sing-box: the addresses of a name it has, and NXDOMAIN for
            // a name it has not, or any other query.
            Kind::Hosts(hosts) => {
                let family = match ty {
                    RecordType::A => Some(IpAddr::is_ipv4 as fn(&IpAddr) -> bool),
                    RecordType::AAAA => Some(IpAddr::is_ipv6 as fn(&IpAddr) -> bool),
                    _ => None,
                };
                Ok(Answer::Message(match (family, hosts.get(host)) {
                    (Some(family), Some(ips)) => {
                        let ips: Vec<IpAddr> = ips.iter().copied().filter(family).collect();
                        Self::reply(request, &ips, HOSTS_TTL)
                    }
                    _ => Self::status(request, ResponseCode::NXDomain),
                }))
            }
            Kind::FakeIp(store) => {
                let v6 = match ty {
                    RecordType::A => false,
                    RecordType::AAAA => true,
                    _ => return Err(anyhow!("a fakeip server answers no {} query", ty)),
                };
                // A family without a range: no address, and no error.
                let ips = match store.serves(v6) {
                    true => vec![store.create(host, v6)?],
                    false => Vec::new(),
                };
                Ok(Answer::Message(Self::reply(request, &ips, FAKE_IP_TTL)))
            }
            Kind::Udp { address, dialer } => {
                let request = request.to_vec()?;
                let addr = self.server_addr(address).await?;
                let socket = self.dial_datagram(dialer, addr).await?;
                self.exchange_udp(socket, &request, addr, server)
                    .await
                    .map(Answer::Message)
            }
            Kind::Tcp {
                address,
                dialer,
                pool,
            } => {
                let request = request.to_vec()?;
                let addr = self.server_addr(address).await?;
                let response = match pool.take() {
                    Some(mut stream) => {
                        match upstream::exchange_framed(&mut stream, &request).await {
                            Ok(response) => {
                                pool.put(stream);
                                response
                            }
                            Err(e) => {
                                debug!("{}: kept connection failed: {}", server, e);
                                self.exchange_tcp(dialer, addr, pool, &request).await?
                            }
                        }
                    }
                    None => self.exchange_tcp(dialer, addr, pool, &request).await?,
                };
                Self::parse(&response, &request, server).map(Answer::Message)
            }
            Kind::Upstream(upstream) => {
                let request = request.to_vec()?;
                let mut last_err = None;
                for _ in 0..self.tuning.max_retries.max(1) {
                    match self.exchange_upstream(upstream, &request).await {
                        Ok(response) => {
                            return Self::parse(&response, &request, server).map(Answer::Message)
                        }
                        Err(e) => {
                            debug!("{} failed: {}", server, e);
                            last_err = Some(e);
                        }
                    }
                }
                Err(last_err.unwrap_or_else(|| anyhow!("no answer")))
            }
            Kind::SmartSelect { .. } => unreachable!("query() takes a smart_select"),
        }
    }

    /// Sends `request` until an answer comes, as many times as
    /// `max_retries` says.
    async fn exchange_udp(
        &self,
        socket: AnyOutboundDatagram,
        request: &[u8],
        addr: SocketAddr,
        server: &Server,
    ) -> Result<Message> {
        let to = SocksAddr::from(addr);
        let (mut r, mut s) = socket.split();
        let attempts = self.tuning.max_retries.max(1);
        // The query's time, shared by the attempts: a datagram lost is sent
        // again.
        let wait = self.timeout / attempts as u32;
        let mut last_err = anyhow!("no answer");
        for _ in 0..attempts {
            if let Err(e) = s.send_to(request, &to).await {
                last_err = anyhow!("send: {}", e);
                continue;
            }
            let deadline = tokio::time::Instant::now() + wait;
            let mut buf = vec![0u8; 4096];
            loop {
                match tokio::time::timeout_at(deadline, r.recv_from(&mut buf)).await {
                    // A late answer to an earlier attempt, or to nothing.
                    Ok(Ok((n, _))) if buf.get(..2) != request.get(..2) || n < 2 => continue,
                    Ok(Ok((n, _))) => return Self::parse(&buf[..n], request, server),
                    Ok(Err(e)) => last_err = anyhow!("receive: {}", e),
                    Err(_) => last_err = anyhow!("timeout"),
                }
                break;
            }
        }
        Err(last_err)
    }

    async fn exchange_tcp(
        &self,
        dialer: &Dialer,
        addr: SocketAddr,
        pool: &upstream::StreamPool,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let mut stream = self.dial_stream(dialer, addr).await?;
        let response = upstream::exchange_framed(&mut stream, request).await?;
        pool.put(stream);
        Ok(response)
    }

    /// An answer to `request`: that the name has records, or that it does
    /// not exist. A server that fails to answer, or refuses to, has not.
    fn parse(response: &[u8], request: &[u8], server: &Server) -> Result<Message> {
        if response.get(..2) != request.get(..2) {
            return Err(anyhow!("{}: an answer to another query", server));
        }
        let message = Message::from_vec(response)
            .map_err(|e| anyhow!("{}: invalid answer: {}", server, e))?;
        match message.response_code() {
            ResponseCode::NoError | ResponseCode::NXDomain => Ok(message),
            code => Err(anyhow!("{}: {}", server, code)),
        }
    }

    /// An answer to `request` made here: `ips` of the family asked for.
    fn reply(request: &Message, ips: &[IpAddr], ttl: u32) -> Message {
        let mut reply = Message::new();
        reply.set_id(request.id());
        reply.set_message_type(MessageType::Response);
        reply.set_op_code(OpCode::Query);
        reply.set_recursion_desired(request.recursion_desired());
        reply.set_recursion_available(true);
        reply.set_response_code(ResponseCode::NoError);
        if let Some(query) = request.queries().first() {
            reply.add_query(query.clone());
            for ip in ips {
                let data = match ip {
                    IpAddr::V4(v4) => RData::A((*v4).into()),
                    IpAddr::V6(v6) => RData::AAAA((*v6).into()),
                };
                reply.add_answer(Record::from_rdata(query.name().clone(), ttl, data));
            }
        }
        reply
    }

    // -- Reading answers -------------------------------------------------

    /// The addresses an answer carries, kept for its TTL.
    fn answer_entry(answer: Answer, host: &str, server: &Server) -> Result<CacheEntry> {
        let (ips, ttl) = match answer {
            Answer::Ips(ips) => (ips, LOCAL_TTL),
            Answer::Message(message) if message.response_code() == ResponseCode::NXDomain => {
                return Err(anyhow!("{}: {} does not exist", server, host));
            }
            Answer::Message(message) => {
                let mut ips = Vec::new();
                for ans in message.answers() {
                    match ans.data() {
                        Some(RData::A(ip)) => ips.push(IpAddr::V4(**ip)),
                        Some(RData::AAAA(ip)) => ips.push(IpAddr::V6(**ip)),
                        _ => (),
                    }
                }
                let ttl = message.answers().first().map_or(0, |ans| ans.ttl());
                (ips, Duration::from_secs(ttl.into()))
            }
        };
        if ips.is_empty() {
            return Err(anyhow!("{}: no address for {}", server, host));
        }
        debug!("{} answered {} {:?} ttl={:?}", server, host, ips, ttl);
        let deadline = Instant::now()
            .checked_add(ttl)
            .ok_or_else(|| anyhow!("invalid ttl"))?;
        Ok(CacheEntry { ips, deadline })
    }

    /// The ECH configs an HTTPS or SVCB answer carries.
    fn ech_entry(
        answer: Answer,
        host: &str,
        server: &Server,
        ty: RecordType,
    ) -> Result<EchCacheEntry> {
        let Answer::Message(message) = answer else {
            return Err(anyhow!("{} answers no {} query", server, ty));
        };
        let mut found = false;
        for ans in message.answers() {
            if ans.record_type() != ty {
                continue;
            }
            let Some(data) = ans.data() else { continue };
            found = true;
            if let Some(ech_config_list) = Self::extract_ech_config_list(&data.to_string()) {
                let deadline = Instant::now()
                    .checked_add(Duration::from_secs(ans.ttl().into()))
                    .ok_or_else(|| anyhow!("invalid ttl"))?;
                debug!("{} answered {} {} with an ech config", server, host, ty);
                return Ok(EchCacheEntry {
                    ech_config_list,
                    deadline,
                });
            }
        }
        if found {
            return Err(anyhow!(
                "missing ech parameter in {} record for {} from {}",
                ty,
                host,
                server
            ));
        }
        Err(anyhow!("no {} records for {} from {}", ty, host, server))
    }

    fn extract_ech_config_list(rdata: &str) -> Option<String> {
        fn extract_quoted(haystack: &str, key: &str) -> Option<String> {
            let start = haystack.find(key)?;
            let rest = &haystack[start + key.len()..];
            let end = rest.find('"')?;
            let value = rest[..end].trim();
            (!value.is_empty()).then(|| value.to_string())
        }

        fn extract_plain(haystack: &str, key: &str) -> Option<String> {
            let start = haystack.find(key)?;
            let rest = &haystack[start + key.len()..];
            let end = rest
                .find(|c: char| c.is_ascii_whitespace() || c == ',')
                .unwrap_or(rest.len());
            let value = rest[..end].trim();
            (!value.is_empty()).then(|| value.to_string())
        }

        extract_quoted(rdata, "echconfig=\"")
            .or_else(|| extract_quoted(rdata, "ech=\""))
            .or_else(|| extract_plain(rdata, "echconfig="))
            .or_else(|| extract_plain(rdata, "ech="))
    }

    fn new_query(name: Name, ty: RecordType) -> Message {
        let mut msg = Message::new();
        msg.add_query(Query::query(name, ty));
        let mut rng = StdRng::from_entropy();
        let id: u16 = rng.gen();
        msg.set_id(id);
        msg.set_op_code(OpCode::Query);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        msg
    }

    // -- Clients' queries ------------------------------------------------

    /// What `ip` is to the fakeip server: a connection to it goes to the
    /// domain it was handed out for.
    pub fn fake_ip(&self, ip: IpAddr) -> FakeIp {
        self.fake_ips
            .as_ref()
            .map_or(FakeIp::NotFake, |store| store.lookup(ip))
    }

    /// The fake IP handed out for `domain`, of the family asked for.
    pub fn fake_ip_of(&self, domain: &str, ipv6: bool) -> Option<IpAddr> {
        self.fake_ips
            .as_ref()
            .and_then(|store| store.address_of(domain, ipv6))
    }

    /// Answers a client's DNS query from the server the rules pick for it:
    /// what the server answered, with the query's ID, or REFUSED for a
    /// rule that rejects it, or SERVFAIL when the server did not answer.
    /// An error only when `query` is not a DNS message.
    pub async fn exchange(&self, query: &[u8], ctx: &LookupContext) -> Result<Vec<u8>> {
        let request = Message::from_vec(query).map_err(|e| anyhow!("not a dns message: {}", e))?;
        let response = self.answer(&request, ctx).await;
        Ok(response.to_vec()?)
    }

    async fn answer(&self, request: &Message, ctx: &LookupContext) -> Message {
        let Some(query) = request.queries().first() else {
            return Self::status(request, ResponseCode::FormErr);
        };
        if request.message_type() != MessageType::Query || request.op_code() != OpCode::Query {
            return Self::status(request, ResponseCode::NotImp);
        }
        let ty = query.query_type();
        let host = query.name().to_utf8();
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let (tag, strategy) = match self.pick(&host, ty, ctx) {
            Pick::Reject => return Self::status(request, ResponseCode::Refused),
            Pick::Server(tag, strategy) => (tag, strategy),
        };
        // A family the strategy leaves out has no records.
        if (ty == RecordType::AAAA && strategy == DnsStrategy::Ipv4Only)
            || (ty == RecordType::A && strategy == DnsStrategy::Ipv6Only)
        {
            return Self::reply(request, &[], LOCAL_TTL.as_secs() as u32);
        }
        let key = (host, u16::from(ty));
        if let Some(cached) = self.cached_answer(&key, request.id()) {
            return cached;
        }
        let server = match self.server(&tag) {
            Ok(server) => server.clone(),
            Err(e) => {
                debug!("{}", e);
                return Self::status(request, ResponseCode::ServFail);
            }
        };
        match self.query(&server, request).await {
            Ok(Answer::Message(mut message)) => {
                message.set_id(request.id());
                // A fake IP comes from its store, which may have handed its
                // address to another domain by the time a cache would.
                if !matches!(server.kind, Kind::FakeIp(_)) {
                    self.cache_answer(key, &message);
                }
                message
            }
            Ok(Answer::Ips(ips)) => Self::reply(request, &ips, LOCAL_TTL.as_secs() as u32),
            Err(e) => {
                debug!("{} from {}: {}", Self::question(request), server, e);
                Self::status(request, ResponseCode::ServFail)
            }
        }
    }

    /// An answer to `request` with no records, and `code`.
    fn status(request: &Message, code: ResponseCode) -> Message {
        let mut status = Self::reply(request, &[], 0);
        status.set_response_code(code);
        status
    }

    /// The answer cached for `key`, with `id` and what is left of its TTLs.
    fn cached_answer(&self, key: &(String, u16), id: u16) -> Option<Message> {
        let mut answers = self.answers.lock().unwrap_or_else(|e| e.into_inner());
        let (message, expires) = answers.get(key)?;
        let now = Instant::now();
        if *expires <= now {
            answers.pop(key);
            return None;
        }
        let left = (*expires - now).as_secs().max(1) as u32;
        let mut message = message.clone();
        message.set_id(id);
        for record in message.answers_mut() {
            record.set_ttl(record.ttl().min(left));
        }
        Some(message)
    }

    /// Keeps `message` for its shortest TTL; one with no records, a
    /// minute.
    fn cache_answer(&self, key: (String, u16), message: &Message) {
        let ttl = message
            .answers()
            .iter()
            .map(|r| r.ttl())
            .min()
            .unwrap_or(LOCAL_TTL.as_secs() as u32);
        if ttl == 0 {
            return;
        }
        let expires = Instant::now() + Duration::from_secs(ttl.into());
        self.answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key, (message.clone(), expires));
    }

    // -- The caches ------------------------------------------------------

    async fn cache_insert(&self, host: &str, entry: CacheEntry) {
        if entry.ips.is_empty() {
            return;
        }
        match entry.ips[0] {
            IpAddr::V4(..) => self.ipv4_cache.lock().await.put(host.to_owned(), entry),
            IpAddr::V6(..) => self.ipv6_cache.lock().await.put(host.to_owned(), entry),
        };
    }

    async fn get_cached(&self, host: &str, strategy: DnsStrategy) -> Option<Vec<IpAddr>> {
        let fetch_order = match strategy {
            DnsStrategy::Ipv4Only => vec![&self.ipv4_cache],
            DnsStrategy::Ipv6Only => vec![&self.ipv6_cache],
            DnsStrategy::PreferIpv4 => vec![&self.ipv4_cache, &self.ipv6_cache],
            DnsStrategy::PreferIpv6 => vec![&self.ipv6_cache, &self.ipv4_cache],
        };
        let mut cached_ips = Vec::new();
        for cache in fetch_order {
            if let Some(entry) = cache.lock().await.get(host) {
                if entry.deadline <= Instant::now() {
                    return None;
                }
                cached_ips.extend_from_slice(&entry.ips);
            }
        }
        (!cached_ips.is_empty()).then_some(cached_ips)
    }

    /// Moves `connected_ip`, which a connection to `address` just reached,
    /// to the front of the cached addresses of `address`.
    pub async fn optimize_cache(&self, address: String, connected_ip: IpAddr) {
        if address.parse::<IpAddr>().is_ok() {
            return;
        }
        let cache = match connected_ip {
            IpAddr::V4(..) => &self.ipv4_cache,
            IpAddr::V6(..) => &self.ipv6_cache,
        };
        let mut cache = cache.lock().await;
        let Some(entry) = cache.get_mut(&address) else {
            return;
        };
        if let Some(idx) = entry.ips.iter().position(|ip| *ip == connected_ip) {
            if idx > 0 {
                trace!("moves {} to the front for {}", connected_ip, address);
                entry.ips[..=idx].rotate_right(1);
            }
        }
    }

    async fn get_cached_ech(&self, host: &str) -> Option<String> {
        let mut cache = self.ech_cache.lock().await;
        if let Some(entry) = cache.get(host) {
            if entry.deadline > Instant::now() {
                return Some(entry.ech_config_list.clone());
            }
        }
        cache.pop(host);
        None
    }

    // -- Lookups ---------------------------------------------------------

    /// The addresses of `host`, from the server the rules pick.
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>> {
        self.lookup_in(host, &LookupContext::default()).await
    }

    /// The addresses of `host`, needed for `ctx`, from the servers the
    /// rules pick for each record type.
    pub async fn lookup_in(&self, host: &str, ctx: &LookupContext) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let a = self.pick(host, RecordType::A, ctx);
        let aaaa = self.pick(host, RecordType::AAAA, ctx);
        // The families: as the rule of the A query says, unless it rejects.
        let strategy = match (&a, &aaaa) {
            (Pick::Server(_, strategy), _) | (Pick::Reject, Pick::Server(_, strategy)) => *strategy,
            (Pick::Reject, Pick::Reject) => {
                return Err(anyhow!("{}: rejected by a dns rule", host));
            }
        };
        let server = |pick: &Pick| match pick {
            Pick::Server(tag, _) => Some(tag.clone()),
            Pick::Reject => None,
        };
        self.lookup_by(host, strategy, server(&a), server(&aaaa))
            .await
    }

    /// The addresses of `host`, which an outbound dials with `dial`: from
    /// its `domain_resolver`, or else from the server the rules pick for
    /// that outbound.
    pub async fn lookup_dial(
        &self,
        host: &str,
        dial: &crate::net::DialOptions,
    ) -> Result<Vec<IpAddr>> {
        match &dial.domain_resolver {
            Some(resolver) => {
                self.lookup_with(
                    &resolver.server,
                    host,
                    resolver.strategy.unwrap_or(self.strategy),
                )
                .await
            }
            None => {
                let ctx = LookupContext {
                    outbound: dial.outbound.clone(),
                    ..Default::default()
                };
                self.lookup_in(host, &ctx).await
            }
        }
    }

    /// The addresses of `host` from the server tagged `server`, of the
    /// families `strategy` says: what the rules have no say in.
    pub async fn lookup_from(
        &self,
        server: &str,
        host: &str,
        strategy: Option<DnsStrategy>,
    ) -> Result<Vec<IpAddr>> {
        self.lookup_with(server, host, strategy.unwrap_or(self.strategy))
            .await
    }

    /// The addresses of `host`, from the server tagged `server`, of the
    /// families `strategy` says: what the rules have no say in.
    #[async_recursion]
    async fn lookup_with(
        &self,
        server: &str,
        host: &str,
        strategy: DnsStrategy,
    ) -> Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        self.lookup_by(
            host,
            strategy,
            Some(server.to_string()),
            Some(server.to_string()),
        )
        .await
    }

    /// The addresses of `host`, of the families `strategy` says: A records
    /// from `server_a`, AAAA ones from `server_aaaa`, none from a family
    /// without a server.
    async fn lookup_by(
        &self,
        host: &str,
        strategy: DnsStrategy,
        server_a: Option<String>,
        server_aaaa: Option<String>,
    ) -> Result<Vec<IpAddr>> {
        // A family is asked for when the strategy wants it and a server
        // takes it.
        let v4 = server_a.is_some() && strategy != DnsStrategy::Ipv6Only;
        let v6 = server_aaaa.is_some() && strategy != DnsStrategy::Ipv4Only;
        let strategy = match (v4, v6) {
            (true, true) => strategy,
            (true, false) => DnsStrategy::Ipv4Only,
            (false, true) => DnsStrategy::Ipv6Only,
            (false, false) => return Err(anyhow!("{}: rejected by a dns rule", host)),
        };
        if let Some(ips) = self.get_cached(host, strategy).await {
            return Ok(ips);
        }
        let name = Name::from_str(&format!("{}.", host))
            .map_err(|e| anyhow!("invalid domain name [{}]: {}", host, e))?;
        let query = |ty, tag: Option<String>| {
            let name = name.clone();
            async move {
                let tag = tag.ok_or_else(|| anyhow!("{} {}: rejected by a dns rule", host, ty))?;
                let server = self.server(&tag)?.clone();
                let answer = self.query(&server, &Self::new_query(name, ty)).await?;
                Self::answer_entry(answer, host, &server)
            }
        };

        let single = match strategy {
            DnsStrategy::Ipv4Only => Some((RecordType::A, server_a.clone())),
            DnsStrategy::Ipv6Only => Some((RecordType::AAAA, server_aaaa.clone())),
            DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 => None,
        };
        if let Some((ty, tag)) = single {
            let entry = query(ty, tag).await?;
            let ips = entry.ips.clone();
            self.cache_insert(host, entry).await;
            return Ok(ips);
        }

        let delay = self.tuning.dualstack_delay;
        let mut a = Box::pin(query(RecordType::A, server_a));
        let mut aaaa = Box::pin(query(RecordType::AAAA, server_aaaa));
        let (first, second) = if strategy == DnsStrategy::PreferIpv6 {
            Self::dualstack_query(&mut aaaa, &mut a, delay).await?
        } else {
            Self::dualstack_query(&mut a, &mut aaaa, delay).await?
        };
        let mut ips = first.ips.clone();
        self.cache_insert(host, first).await;
        if let Some(second) = second {
            ips.extend_from_slice(&second.ips);
            self.cache_insert(host, second).await;
        }
        Ok(ips)
    }

    /// The answer of `preferred`, or of `fallback` when `preferred` has
    /// none within `delay`, and the other one too if it is already there.
    async fn dualstack_query<P, F>(
        preferred: &mut P,
        fallback: &mut F,
        delay: Duration,
    ) -> Result<(CacheEntry, Option<CacheEntry>)>
    where
        P: std::future::Future<Output = Result<CacheEntry>> + Unpin,
        F: std::future::Future<Output = Result<CacheEntry>> + Unpin,
    {
        let delay_fut = tokio::time::sleep(delay);
        tokio::pin!(delay_fut);

        let first = tokio::select! {
            biased;
            r = &mut *preferred => Some((true, r)),
            _ = &mut delay_fut => None,
        };

        let (first_is_preferred, first_res) = match first {
            Some(v) => v,
            None => tokio::select! {
                r = &mut *preferred => (true, r),
                r = &mut *fallback => (false, r),
            },
        };

        match first_res {
            Ok(entry) => {
                let other = if first_is_preferred {
                    match timeout(Duration::from_millis(0), &mut *fallback).await {
                        Ok(Ok(e)) => Some(e),
                        _ => None,
                    }
                } else {
                    match timeout(Duration::from_millis(0), &mut *preferred).await {
                        Ok(Ok(e)) => Some(e),
                        _ => None,
                    }
                };
                Ok((entry, other))
            }
            Err(err1) => {
                let second_res = if first_is_preferred {
                    (&mut *fallback).await
                } else {
                    (&mut *preferred).await
                };
                match second_res {
                    Ok(entry) => Ok((entry, None)),
                    Err(err2) => Err(anyhow!("all dns queries failed: {}; {}", err1, err2)),
                }
            }
        }
    }

    /// The ECH configs `host` publishes, in an HTTPS record or else an SVCB
    /// one, from the server the rules pick.
    pub async fn lookup_ech_config_list(&self, host: &str) -> Result<String> {
        if let Some(cached) = self.get_cached_ech(host).await {
            return Ok(cached);
        }
        let host_lock = {
            let mut locks = self.ech_query_locks.lock().await;
            locks
                .entry(host.to_owned())
                .or_insert_with(|| Arc::new(TokioMutex::new(())))
                .clone()
        };
        let _query_guard = host_lock.lock().await;
        let result = match self.get_cached_ech(host).await {
            Some(cached) => Ok(cached),
            None => match self.query_ech(host).await {
                Ok(entry) => {
                    let list = entry.ech_config_list.clone();
                    self.ech_cache.lock().await.put(host.to_owned(), entry);
                    Ok(list)
                }
                Err(e) => Err(e),
            },
        };
        {
            let mut locks = self.ech_query_locks.lock().await;
            if let Some(current) = locks.get(host) {
                if Arc::ptr_eq(current, &host_lock) {
                    locks.remove(host);
                }
            }
        }
        result
    }

    async fn query_ech(&self, host: &str) -> Result<EchCacheEntry> {
        let name = Name::from_str(&format!("{}.", host))
            .map_err(|e| anyhow!("invalid domain name [{}]: {}", host, e))?;
        let mut errors = Vec::new();
        for ty in [RecordType::HTTPS, RecordType::SVCB] {
            let server = match self.pick(host, ty, &LookupContext::default()) {
                Pick::Server(tag, _) => self.server(&tag)?.clone(),
                Pick::Reject => {
                    errors.push(format!("{}: rejected by a dns rule", ty));
                    continue;
                }
            };
            match self
                .query(&server, &Self::new_query(name.clone(), ty))
                .await
            {
                Ok(answer) => match Self::ech_entry(answer, host, &server, ty) {
                    Ok(entry) => return Ok(entry),
                    Err(e) => errors.push(format!("{}: {}", ty, e)),
                },
                Err(e) => errors.push(format!("{}: {}", ty, e)),
            }
        }
        Err(anyhow!(
            "ech query failed for {}: {}",
            host,
            errors.join("; ")
        ))
    }
}

include!("client/tests.rs");
