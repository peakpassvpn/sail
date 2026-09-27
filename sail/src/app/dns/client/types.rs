#[derive(Clone, Debug)]
struct CacheEntry {
    pub ips: Vec<IpAddr>,
    pub deadline: Instant,
}

#[derive(Clone, Debug)]
pub struct EchCacheEntry {
    pub ech_config_list: String,
    pub deadline: Instant,
}

/// What a server answered.
enum Answer {
    /// A DNS message, from a server asked over the wire.
    Message(Message),
    /// Addresses, from the system's resolver or a hosts server, which have
    /// no message and no TTL of their own.
    Ips(Vec<IpAddr>),
}

#[derive(Clone, Debug, Default)]
struct ServerRuntimeStats {
    avg_latency_ms: f64,
    samples: u64,
    successes: u64,
    failures: u64,
    timeouts: u64,
    consecutive_slow: u32,
    consecutive_failures: u32,
}

/// How the members of a smart_select have fared, by tag, and which one is
/// asked first.
#[derive(Clone, Debug, Default)]
struct ServerSelectorState {
    primary_server: Option<String>,
    stats: HashMap<String, ServerRuntimeStats>,
    last_reselect_at: Option<Instant>,
    tuning: crate::runtime::options::Dns,
}

impl ServerSelectorState {
    fn score_of(&self, server: &str) -> f64 {
        if let Some(stat) = self.stats.get(server) {
            let baseline = if stat.samples == 0 {
                self.slow_response_ms() / 2.0
            } else {
                stat.avg_latency_ms
            };
            baseline
                + (stat.failures as f64 * 600.0)
                + (stat.timeouts as f64 * 900.0)
                + (stat.consecutive_failures as f64 * 1200.0)
                + (stat.consecutive_slow as f64 * 300.0)
        } else {
            self.slow_response_ms() / 2.0
        }
    }

    fn slow_response_ms(&self) -> f64 {
        (self.tuning.slow_response.as_millis() as f64).max(1.0)
    }

    fn is_degraded(&self, server: &str) -> bool {
        let switch_threshold = self.tuning.switch_threshold.max(1);
        if let Some(stat) = self.stats.get(server) {
            (stat.consecutive_failures as usize) >= switch_threshold
                || (stat.consecutive_slow as usize) >= switch_threshold
        } else {
            false
        }
    }

    fn select_primary_index(&mut self, servers: &[String]) -> usize {
        if servers.len() <= 1 {
            if let Some(server) = servers.first() {
                self.primary_server = Some(server.clone());
            }
            return 0;
        }
        for server in servers {
            self.stats.entry(server.clone()).or_default();
        }
        let now = Instant::now();
        let reselect_interval = self.tuning.reselect_interval.max(Duration::from_secs(1));
        let should_reselect = self
            .last_reselect_at
            .map(|last| now.saturating_duration_since(last) >= reselect_interval)
            .unwrap_or(true);

        let current_idx = self
            .primary_server
            .as_ref()
            .and_then(|primary| servers.iter().position(|server| server == primary));
        if let Some(idx) = current_idx {
            if !should_reselect && !self.is_degraded(&servers[idx]) {
                return idx;
            }
        }

        let mut best_idx = 0usize;
        let mut best_score = f64::MAX;
        for (idx, server) in servers.iter().enumerate() {
            let score = self.score_of(server);
            if score < best_score {
                best_score = score;
                best_idx = idx;
            }
        }
        self.primary_server = Some(servers[best_idx].clone());
        self.last_reselect_at = Some(now);
        best_idx
    }

    fn fallback_indices(&self, servers: &[String], preferred_idx: usize) -> Vec<usize> {
        let mut candidates: Vec<usize> = (0..servers.len())
            .filter(|idx| *idx != preferred_idx)
            .collect();
        candidates.sort_by(|a, b| {
            let sa = self.score_of(&servers[*a]);
            let sb = self.score_of(&servers[*b]);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        });
        candidates
    }

    fn mark_success(&mut self, server: &str, elapsed: Duration) {
        let slow_threshold = self.slow_response_ms();
        let stat = self.stats.entry(server.to_owned()).or_default();
        let elapsed_ms = elapsed.as_millis() as f64;
        stat.successes = stat.successes.saturating_add(1);
        stat.samples = stat.samples.saturating_add(1);
        if stat.samples == 1 {
            stat.avg_latency_ms = elapsed_ms;
        } else {
            stat.avg_latency_ms = stat.avg_latency_ms * 0.8 + elapsed_ms * 0.2;
        }
        if elapsed_ms >= slow_threshold {
            stat.consecutive_slow = stat.consecutive_slow.saturating_add(1);
        } else {
            stat.consecutive_slow = 0;
        }
        stat.consecutive_failures = 0;
        if self.primary_server.is_none() {
            self.primary_server = Some(server.to_owned());
        }
    }

    fn mark_failure(&mut self, server: &str, is_timeout: bool) {
        let stat = self.stats.entry(server.to_owned()).or_default();
        stat.failures = stat.failures.saturating_add(1);
        if is_timeout {
            stat.timeouts = stat.timeouts.saturating_add(1);
        }
        stat.consecutive_failures = stat.consecutive_failures.saturating_add(1);
        let switch_threshold = self.tuning.switch_threshold.max(1);
        if self.primary_server.as_deref() == Some(server)
            && (stat.consecutive_failures as usize) >= switch_threshold
        {
            self.primary_server = None;
        }
    }

    fn set_primary(&mut self, server: &str) {
        self.primary_server = Some(server.to_owned());
        self.last_reselect_at = Some(Instant::now());
    }
}

/// A DNS rule, compiled.
struct Rule {
    /// The domain, inbound and user conditions, as a routing rule has them.
    matcher: crate::app::router::matcher::Matcher,
    query_types: Vec<RecordType>,
    action: RuleAction,
}

enum RuleAction {
    Route {
        server: String,
        strategy: Option<DnsStrategy>,
    },
    Reject,
}

/// What a lookup is for: the DNS rules match it.
#[derive(Debug, Clone, Default)]
pub struct LookupContext {
    /// The inbound the connection that needs the name came in through.
    pub inbound: Option<String>,
    /// The user an inbound authenticated.
    pub user: Option<Arc<str>>,
}

/// Where a query of one record type goes, as the rules say.
#[derive(Debug, Clone, PartialEq)]
enum Pick {
    Server(String, DnsStrategy),
    Reject,
}

pub struct DnsClient {
    /// Set once the dispatcher exists, and kept across reloads.
    dispatcher: Arc<std::sync::OnceLock<Weak<Dispatcher>>>,
    /// `dns.servers`, by tag.
    servers: HashMap<String, Arc<server::Server>>,
    /// `dns.rules`.
    rules: Vec<Rule>,
    /// `dns.final`.
    final_server: String,
    ipv4_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ipv6_cache: Arc<TokioMutex<LruCache<String, CacheEntry>>>,
    ech_cache: Arc<TokioMutex<LruCache<String, EchCacheEntry>>>,
    ech_query_locks: Arc<TokioMutex<HashMap<String, Arc<TokioMutex<()>>>>>,
    tuning: crate::runtime::options::Dns,
    /// `dns.strategy`.
    strategy: crate::config::model::DnsStrategy,
    /// `dns.timeout`: how long one query to one server may take.
    timeout: Duration,
    /// `dns.reverse_mapping`.
    reverse_mapping: bool,
}
