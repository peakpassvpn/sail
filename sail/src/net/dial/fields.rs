//! sing-box's dial fields, read the same way wherever a configuration
//! gives them.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::config::model::{DnsStrategy, DomainResolver};

/// How something dials: sing-box's dial fields (`DialerOptions` in 1.14),
/// by their names, and one sail extension. Outbounds and endpoints, DNS
/// servers, HTTP clients and REALITY's handshake take them, flattened into
/// their own objects, and each checks them with [`DialFields::check`]
/// against the fields it implements.
///
/// The fields sail does not implement yet are read as any value, so that a
/// place names them as such rather than as unknown; a sing-box
/// configuration has them sorted out before, as `config::singbox::upstream`
/// says.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct DialFields {
    /// The outbound to dial through, in place of a socket of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    /// The interface to send through, by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    /// The local address for IPv4 destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet4_bind_address: Option<Ipv4Addr>,
    /// The local address for IPv6 destinations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet6_bind_address: Option<Ipv6Addr>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_address_no_port: Option<Value>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protect_path: Option<Value>,
    /// `SO_MARK`, Linux only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<u32>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse_addr: Option<Value>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netns: Option<Value>,
    /// How long a TCP connect to one address may take; 5s when unset.
    #[serde(
        default,
        with = "crate::config::model::duration",
        skip_serializing_if = "Option::is_none"
    )]
    pub connect_timeout: Option<Duration>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fast_open: Option<Value>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_multi_path: Option<Value>,
    /// No TCP keepalive at all.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_tcp_keep_alive: bool,
    /// How long a TCP connection is idle before keepalive probes it; 5m
    /// when unset.
    #[serde(
        default,
        with = "crate::config::model::duration",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_keep_alive: Option<Duration>,
    /// Between keepalive probes; 75s when unset.
    #[serde(
        default,
        with = "crate::config::model::duration",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp_keep_alive_interval: Option<Duration>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_fragment: Option<Value>,
    /// The DNS server that resolves the names dialled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_resolver: Option<DomainResolver>,
    /// A sail extension: without a `domain_resolver` of its own, the names
    /// dialled resolve as the DNS rules say, not as
    /// `route.default_domain_resolver` does; as Mihomo's DIRECT resolves
    /// apart from the proxies' servers.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skip_default_domain_resolver: bool,
    /// sing-box's deprecated field for the families names resolve to,
    /// which a resolver's own `strategy` goes before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<DnsStrategy>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_strategy: Option<Value>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_type: Option<Value>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_network_type: Option<Value>,
    /// Not implemented yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_delay: Option<Value>,
}

/// The fields sail implements, where it implements them all: outbounds and
/// endpoints.
pub const IMPLEMENTED: &[&str] = &[
    "detour",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "routing_mark",
    "connect_timeout",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "domain_resolver",
    "skip_default_domain_resolver",
    "domain_strategy",
];

/// The fields that shape the socket itself, which a detour replaces.
const SOCKET: &[&str] = &[
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "bind_address_no_port",
    "protect_path",
    "routing_mark",
    "reuse_addr",
    "netns",
    "connect_timeout",
    "tcp_fast_open",
    "tcp_multi_path",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "udp_fragment",
    "network_strategy",
    "network_type",
    "fallback_network_type",
    "fallback_delay",
];

impl DialFields {
    /// The names of the fields, as a configuration spells them.
    pub fn names() -> &'static [&'static str] {
        static NAMES: OnceLock<&'static [&'static str]> = OnceLock::new();
        NAMES.get_or_init(|| {
            let mut names: &'static [&'static str] = &[];
            let _ = DialFields::deserialize(Names(&mut names));
            names
        })
    }

    /// The names of the fields that are set, in the order of the struct.
    pub fn set(&self) -> impl Iterator<Item = &'static str> {
        [
            ("detour", self.detour.is_some()),
            ("bind_interface", self.bind_interface.is_some()),
            ("inet4_bind_address", self.inet4_bind_address.is_some()),
            ("inet6_bind_address", self.inet6_bind_address.is_some()),
            ("bind_address_no_port", self.bind_address_no_port.is_some()),
            ("protect_path", self.protect_path.is_some()),
            ("routing_mark", self.routing_mark.is_some()),
            ("reuse_addr", self.reuse_addr.is_some()),
            ("netns", self.netns.is_some()),
            ("connect_timeout", self.connect_timeout.is_some()),
            ("tcp_fast_open", self.tcp_fast_open.is_some()),
            ("tcp_multi_path", self.tcp_multi_path.is_some()),
            ("disable_tcp_keep_alive", self.disable_tcp_keep_alive),
            ("tcp_keep_alive", self.tcp_keep_alive.is_some()),
            (
                "tcp_keep_alive_interval",
                self.tcp_keep_alive_interval.is_some(),
            ),
            ("udp_fragment", self.udp_fragment.is_some()),
            ("domain_resolver", self.domain_resolver.is_some()),
            (
                "skip_default_domain_resolver",
                self.skip_default_domain_resolver,
            ),
            ("domain_strategy", self.domain_strategy.is_some()),
            ("network_strategy", self.network_strategy.is_some()),
            ("network_type", self.network_type.is_some()),
            (
                "fallback_network_type",
                self.fallback_network_type.is_some(),
            ),
            ("fallback_delay", self.fallback_delay.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, set)| set.then_some(name))
    }

    /// The first field set that shapes the socket itself.
    pub fn socket_field(&self) -> Option<&'static str> {
        self.set().find(|name| SOCKET.contains(name))
    }

    /// Checks the fields against those the place implements, `taken`, and
    /// against each other. The error names the field; the place puts
    /// where it is before it.
    pub fn check(&self, taken: &[&str]) -> Result<()> {
        if let Some(name) = self.set().find(|name| !taken.contains(name)) {
            return Err(anyhow!("{}: sail does not implement this field yet", name));
        }
        if self.skip_default_domain_resolver && self.domain_resolver.is_some() {
            return Err(anyhow!(
                "skip_default_domain_resolver: not with a domain_resolver, \
                 which the default never replaces"
            ));
        }
        if let (Some(detour), Some(name)) = (&self.detour, self.socket_field()) {
            return Err(anyhow!(
                "{}: has no effect with a detour; set it on [{}]",
                name,
                detour
            ));
        }
        Ok(())
    }

    /// Its `domain_resolver`, `domain_strategy` giving the strategy where
    /// the resolver gives none.
    pub fn domain_resolver(&self) -> Option<DomainResolver> {
        self.domain_resolver.clone().map(|resolver| DomainResolver {
            strategy: resolver.strategy.or(self.domain_strategy),
            ..resolver
        })
    }
}

impl Serialize for DialFields {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        DialFields::serialize(self, s)
    }
}

impl<'de> Deserialize<'de> for DialFields {
    /// Flattened into another object, as the fields always are, serde's
    /// error for one would name that object and not the field. They are
    /// taken out and read apart, and the error names the field in the
    /// object: `routing_mark: invalid type ...`.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let fields = d.deserialize_struct("DialFields", DialFields::names(), Collect)?;
        serde_path_to_error::deserialize(Value::Object(fields))
            .map(|Derived(fields)| fields)
            .map_err(|e| match e.path().to_string().as_str() {
                "." => de::Error::custom(e.inner()),
                path => de::Error::custom(format_args!("{}: {}", path, e.inner())),
            })
    }
}

/// The derived reading.
struct Derived(DialFields);

impl<'de> Deserialize<'de> for Derived {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        DialFields::deserialize(d).map(Derived)
    }
}

/// Takes the entries of a map as they are.
struct Collect;

impl<'de> Visitor<'de> for Collect {
    type Value = serde_json::Map<String, Value>;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("dial fields")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut fields = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            fields.insert(key, value);
        }
        Ok(fields)
    }
}

/// A deserializer that reads nothing, and notes the field names a struct
/// asks it for.
struct Names<'a>(&'a mut &'static [&'static str]);

impl<'de> Deserializer<'de> for Names<'_> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        Err(de::Error::custom("not a struct"))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Self::Error> {
        *self.0 = fields;
        Err(de::Error::custom("names taken"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

/// The keepalive the system gives a TCP connection dialled by `dialer`.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn keepalive_dialled(dialer: &super::Dialer) -> Option<super::TcpKeepAlive> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (dialled, accepted) = tokio::join!(dialer.tcp_to(addr), listener.accept());
    let (dialled, _accepted) = (dialled.unwrap(), accepted.unwrap());
    let socket = socket2::SockRef::from(&dialled);
    socket.keepalive().unwrap().then(|| super::TcpKeepAlive {
        idle: socket.keepalive_time().unwrap(),
        interval: socket.keepalive_interval().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// sing-box 1.14's `DialerOptions`, by the names its JSON gives them.
    const SING_BOX: &[&str] = &[
        "detour",
        "bind_interface",
        "inet4_bind_address",
        "inet6_bind_address",
        "bind_address_no_port",
        "protect_path",
        "routing_mark",
        "reuse_addr",
        "netns",
        "connect_timeout",
        "tcp_fast_open",
        "tcp_multi_path",
        "disable_tcp_keep_alive",
        "tcp_keep_alive",
        "tcp_keep_alive_interval",
        "udp_fragment",
        "domain_resolver",
        "network_strategy",
        "network_type",
        "fallback_network_type",
        "fallback_delay",
        "domain_strategy",
    ];

    #[test]
    fn the_fields_are_sing_box_s_and_one_extension() {
        let mut names = DialFields::names().to_vec();
        names.sort_unstable();
        let mut want = SING_BOX.to_vec();
        want.push("skip_default_domain_resolver");
        want.sort_unstable();
        assert_eq!(names, want);
        // `set` knows each of them.
        let all: DialFields = serde_json::from_value(serde_json::json!({
            "detour": "d", "bind_interface": "i", "inet4_bind_address": "192.0.2.1",
            "inet6_bind_address": "2001:db8::1", "bind_address_no_port": true,
            "protect_path": "p", "routing_mark": 1, "reuse_addr": true, "netns": "n",
            "connect_timeout": "1s", "tcp_fast_open": true, "tcp_multi_path": true,
            "disable_tcp_keep_alive": true, "tcp_keep_alive": "1m",
            "tcp_keep_alive_interval": "1s", "udp_fragment": true,
            "domain_resolver": "dns", "skip_default_domain_resolver": true,
            "domain_strategy": "ipv4_only", "network_strategy": "hybrid",
            "network_type": ["wifi"], "fallback_network_type": ["cellular"],
            "fallback_delay": "300ms",
        }))
        .unwrap();
        assert_eq!(all.set().count(), names.len());
        for name in IMPLEMENTED.iter().chain(SOCKET) {
            assert!(names.contains(name), "{}", name);
        }
    }

    #[test]
    fn an_error_names_the_field() {
        #[derive(Deserialize, Debug)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct Place {
            #[serde(default)]
            server: Option<String>,
            #[serde(flatten)]
            dial: DialFields,
        }
        let err = |json: serde_json::Value| {
            let e = serde_path_to_error::deserialize::<_, Place>(json).unwrap_err();
            format!("{}: {}", e.path(), e.inner())
        };
        assert_eq!(
            err(serde_json::json!({ "routing_mark": "x" })),
            r#".: routing_mark: invalid type: string "x", expected u32"#
        );
        assert_eq!(
            err(serde_json::json!({ "domain_resolver": { "server": "a", "strategy": "x" } })),
            ".: domain_resolver: unknown variant `x`, expected one of \
             `prefer_ipv4`, `prefer_ipv6`, `ipv4_only`, `ipv6_only`"
        );
        assert_eq!(
            err(serde_json::json!({ "routing_markk": 1 })),
            ".: unknown field `routing_markk`"
        );
        let place: Place = serde_json::from_value(serde_json::json!({
            "server": "a", "routing_mark": 7, "tcp_keep_alive": "1m",
        }))
        .unwrap();
        assert_eq!(place.dial.routing_mark, Some(7));
        assert_eq!(place.dial.tcp_keep_alive, Some(Duration::from_secs(60)));
        // Written back, they are fields of the place again.
        #[derive(Serialize)]
        struct Written<'a> {
            server: &'a str,
            #[serde(flatten)]
            dial: &'a DialFields,
        }
        assert_eq!(
            serde_json::to_value(Written {
                server: "a",
                dial: &place.dial
            })
            .unwrap(),
            serde_json::json!({ "server": "a", "routing_mark": 7, "tcp_keep_alive": "60000ms" })
        );
    }

    #[test]
    fn checked_against_the_place_and_each_other() {
        let fields =
            |json: serde_json::Value| -> DialFields { serde_json::from_value(json).unwrap() };
        let check = |json: serde_json::Value, taken: &[&str]| {
            fields(json).check(taken).map_err(|e| e.to_string())
        };
        assert_eq!(
            check(serde_json::json!({ "tcp_fast_open": true }), IMPLEMENTED),
            Err("tcp_fast_open: sail does not implement this field yet".into())
        );
        assert_eq!(
            check(
                serde_json::json!({ "tcp_keep_alive": "1m" }),
                &["routing_mark"]
            ),
            Err("tcp_keep_alive: sail does not implement this field yet".into())
        );
        assert_eq!(
            check(
                serde_json::json!({ "detour": "d", "tcp_keep_alive": "1m" }),
                IMPLEMENTED
            ),
            Err("tcp_keep_alive: has no effect with a detour; set it on [d]".into())
        );
        assert_eq!(
            check(
                serde_json::json!({ "domain_resolver": "a", "skip_default_domain_resolver": true }),
                IMPLEMENTED
            ),
            Err("skip_default_domain_resolver: not with a domain_resolver, \
                 which the default never replaces"
                .into())
        );
        check(
            serde_json::json!({ "detour": "d", "domain_resolver": "a" }),
            IMPLEMENTED,
        )
        .unwrap();
    }
}
