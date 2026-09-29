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

/// A DNS rule, compiled.
struct Rule {
    /// The domain, inbound and user conditions, as a routing rule has them.
    matcher: crate::app::router::matcher::Matcher,
    outbounds: Vec<String>,
    /// The evaluated response it matches, whose addresses and code the
    /// matcher sees.
    response: Option<crate::config::model::ResponseRef>,
    /// Whether it is inverted: without its response, it matches only then.
    invert: bool,
    /// Whether its conditions on the response's addresses hold for each.
    ip_match_all: bool,
    action: RuleAction,
}

enum RuleAction {
    Route {
        server: String,
        strategy: Option<DnsStrategy>,
        options: QueryOptions,
    },
    Evaluate {
        server: String,
        tag: Option<String>,
        options: QueryOptions,
    },
    /// Answers with the response the rule names, or the latest.
    Respond,
    RouteOptions(QueryOptions),
    Reject,
    /// Answers with this code and no records.
    Predefined(ResponseCode),
}

/// How a query is sent: what rules' route options set.
#[derive(Debug, Clone, Default, PartialEq)]
struct QueryOptions {
    disable_cache: bool,
    disable_optimistic_cache: bool,
    rewrite_ttl: Option<u32>,
    timeout: Option<Duration>,
    /// Unset, `dns.client_subnet`.
    client_subnet: Option<Subnet>,
}

/// The EDNS Client Subnet a query carries.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Subnet {
    Set(crate::config::model::Prefix),
    Remove,
}

impl QueryOptions {
    fn of(rule: &crate::config::model::DnsRule) -> Self {
        QueryOptions {
            disable_cache: rule.disable_cache,
            disable_optimistic_cache: rule.disable_optimistic_cache,
            rewrite_ttl: rule.rewrite_ttl,
            timeout: rule.timeout,
            client_subnet: match (rule.client_subnet, rule.remove_client_subnet) {
                (_, true) => Some(Subnet::Remove),
                (Some(prefix), false) => Some(Subnet::Set(prefix)),
                (None, false) => None,
            },
        }
    }

    /// How a `domain_resolver`'s queries are sent.
    fn of_resolver(resolver: &crate::config::model::DomainResolver) -> Self {
        QueryOptions {
            disable_cache: resolver.disable_cache,
            disable_optimistic_cache: resolver.disable_optimistic_cache,
            rewrite_ttl: resolver.rewrite_ttl,
            timeout: resolver.timeout,
            client_subnet: resolver.client_subnet.map(Subnet::Set),
        }
    }

    /// These, with what `later` sets over them.
    fn with(&self, later: &QueryOptions) -> QueryOptions {
        QueryOptions {
            disable_cache: self.disable_cache || later.disable_cache,
            disable_optimistic_cache: self.disable_optimistic_cache
                || later.disable_optimistic_cache,
            rewrite_ttl: later.rewrite_ttl.or(self.rewrite_ttl),
            timeout: later.timeout.or(self.timeout),
            client_subnet: later.client_subnet.or(self.client_subnet),
        }
    }
}

/// What a lookup is for: the DNS rules match it.
#[derive(Debug, Clone, Default)]
pub struct LookupContext {
    /// The inbound the connection that needs the name came in through.
    pub inbound: Option<String>,
    /// The user an inbound authenticated.
    pub user: Option<Arc<str>>,
    /// The outbound that dials the name.
    pub outbound: Option<String>,
    /// The address families, over what the rules and `dns.strategy` say.
    pub strategy: Option<DnsStrategy>,
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
    ech_cache: Arc<TokioMutex<LruCache<String, EchCacheEntry>>>,
    ech_query_locks: Arc<TokioMutex<HashMap<String, Arc<TokioMutex<()>>>>>,
    /// The answers each server gave, as `dns` keeps them.
    answers: Arc<cache::Answers>,
    /// `dns.disable_cache`.
    disable_cache: bool,
    /// The client itself, once shared, for what it does in the background.
    me: Weak<DnsClient>,
    /// The fakeip server's store, when there is one.
    fake_ips: Option<Arc<fakeip::FakeIpStore>>,
    tuning: crate::runtime::options::Dns,
    /// `dns.strategy`.
    strategy: crate::config::model::DnsStrategy,
    /// `dns.timeout`: how long one query to one server may take.
    timeout: Duration,
    /// `dns.reverse_mapping`.
    reverse_mapping: bool,
    /// `dns.client_subnet`.
    client_subnet: Option<crate::config::model::Prefix>,
    /// Whether any rule has a `strategy` of its own, which then decides
    /// the families of a lookup.
    rules_set_strategy: bool,
}
