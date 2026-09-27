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
    rr::{record_data::RData, record_type::RecordType, Name},
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

mod server;
mod upstream;

use server::{Address, Dialer, Kind, Server};

/// How long the system resolver's and a hosts server's answers are kept:
/// they carry no TTL.
const LOCAL_TTL: Duration = Duration::from_secs(60);

impl DnsClient {
    pub fn new(
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialOptions>,
        env: &crate::runtime::RuntimeEnv,
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
        for config in configs {
            let server = Server::new(config, &dial, env, &tuning)?;
            debug!("dns server {}", server);
            servers.insert(config.tag.clone(), Arc::new(server));
        }
        server::check(&servers)?;
        let final_server = dns
            .final_server
            .clone()
            .unwrap_or_else(|| configs[0].tag.clone());
        let capacity = NonZeroUsize::new(dns.cache_capacity())
            .ok_or_else(|| anyhow!("dns.cache_capacity: must be at least 1"))?;
        Ok(Self {
            dispatcher: Default::default(),
            servers,
            final_server,
            ipv4_cache: Arc::new(TokioMutex::new(LruCache::new(capacity))),
            ipv6_cache: Arc::new(TokioMutex::new(LruCache::new(capacity))),
            ech_cache: Arc::new(TokioMutex::new(LruCache::new(capacity))),
            ech_query_locks: Arc::new(TokioMutex::new(HashMap::new())),
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
    pub fn reloaded(
        &self,
        dns: &crate::config::Dns,
        dial: Arc<crate::net::DialOptions>,
        env: &crate::runtime::RuntimeEnv,
    ) -> Result<Self> {
        let mut client = Self::new(dns, dial, env)?;
        client.dispatcher = self.dispatcher.clone();
        Ok(client)
    }

    /// Whether `dns.reverse_mapping` is on.
    pub fn reverse_mapping(&self) -> bool {
        self.reverse_mapping
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

    /// Asks `server` about `name`, within the query's time; a smart_select
    /// asks its members, as they have fared.
    #[async_recursion]
    async fn query(&self, server: &Server, name: &Name, ty: RecordType) -> Result<Answer> {
        if let Kind::SmartSelect { members, state } = &server.kind {
            return self.query_selected(members, state, name, ty).await;
        }
        match timeout(self.timeout, self.ask(server, name, ty)).await {
            Ok(res) => res,
            Err(_) => Err(anyhow!("{} {} {}: timeout", server, name, ty)),
        }
    }

    /// Asks the member that fares best, then the others, as many at once
    /// as `fallback_concurrency` says, as they fare.
    async fn query_selected(
        &self,
        members: &[String],
        state: &std::sync::Mutex<ServerSelectorState>,
        name: &Name,
        ty: RecordType,
    ) -> Result<Answer> {
        let lock = || state.lock().unwrap_or_else(|e| e.into_inner());
        let ask = |idx: usize| {
            let tag = &members[idx];
            async move {
                let server = self.server(tag)?;
                let start = tokio::time::Instant::now();
                match self.query(server, name, ty).await {
                    Ok(answer) => {
                        lock().mark_success(tag, start.elapsed());
                        Ok((idx, answer))
                    }
                    Err(e) => {
                        let is_timeout = e.to_string().contains("timeout");
                        lock().mark_failure(tag, is_timeout);
                        debug!("{} {} failed with [{}]: {}", name, ty, tag, e);
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
    async fn ask(&self, server: &Server, name: &Name, ty: RecordType) -> Result<Answer> {
        let host = name.to_utf8();
        let host = host.trim_end_matches('.');
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
            Kind::Hosts(hosts) => {
                let family = match ty {
                    RecordType::A => IpAddr::is_ipv4,
                    RecordType::AAAA => IpAddr::is_ipv6,
                    _ => return Err(anyhow!("a hosts server answers no {} query", ty)),
                };
                let ips = hosts
                    .get(&host.to_ascii_lowercase())
                    .ok_or_else(|| anyhow!("{}: no such name in {}", host, server))?;
                Ok(Answer::Ips(ips.iter().copied().filter(family).collect()))
            }
            Kind::Udp { address, dialer } => {
                let request = Self::new_query(name.clone(), ty).to_vec()?;
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
                let request = Self::new_query(name.clone(), ty).to_vec()?;
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
                let request = Self::new_query(name.clone(), ty).to_vec()?;
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

    /// An answer to `request`, and not an error.
    fn parse(response: &[u8], request: &[u8], server: &Server) -> Result<Message> {
        if response.get(..2) != request.get(..2) {
            return Err(anyhow!("{}: an answer to another query", server));
        }
        let message = Message::from_vec(response)
            .map_err(|e| anyhow!("{}: invalid answer: {}", server, e))?;
        if message.response_code() != ResponseCode::NoError {
            return Err(anyhow!("{}: {}", server, message.response_code()));
        }
        Ok(message)
    }

    // -- Reading answers -------------------------------------------------

    /// The addresses an answer carries, kept for its TTL.
    fn answer_entry(answer: Answer, host: &str, server: &Server) -> Result<CacheEntry> {
        let (ips, ttl) = match answer {
            Answer::Ips(ips) => (ips, LOCAL_TTL),
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

    /// The addresses of `host`, from the final server.
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>> {
        let server = self.final_server.clone();
        self.lookup_with(&server, host, self.strategy).await
    }

    /// The addresses of `host`, from the server tagged `server`, of the
    /// families `strategy` says.
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
        if let Some(ips) = self.get_cached(host, strategy).await {
            return Ok(ips);
        }
        let server = self.server(server)?.clone();
        let name = Name::from_str(&format!("{}.", host))
            .map_err(|e| anyhow!("invalid domain name [{}]: {}", host, e))?;
        let query = |ty| {
            let server = server.clone();
            let name = name.clone();
            async move {
                let answer = self.query(&server, &name, ty).await?;
                Self::answer_entry(answer, host, &server)
            }
        };

        let single = match strategy {
            DnsStrategy::Ipv4Only => Some(RecordType::A),
            DnsStrategy::Ipv6Only => Some(RecordType::AAAA),
            DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 => None,
        };
        if let Some(ty) = single {
            let entry = query(ty).await?;
            let ips = entry.ips.clone();
            self.cache_insert(host, entry).await;
            return Ok(ips);
        }

        let delay = self.tuning.dualstack_delay;
        let mut a = Box::pin(query(RecordType::A));
        let mut aaaa = Box::pin(query(RecordType::AAAA));
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
    /// one, from the final server.
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
        let server = self.server(&self.final_server)?.clone();
        let mut errors = Vec::new();
        for ty in [RecordType::HTTPS, RecordType::SVCB] {
            match self.query(&server, &name, ty).await {
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
