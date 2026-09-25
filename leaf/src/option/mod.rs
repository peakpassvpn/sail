use std::env;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;

use lazy_static::lazy_static;

// Gets an environment variable by a key and parses as type `T` or returns
// the provided default value.
pub fn get_env_var_or<T>(key: &str, default: T) -> T
where
    T: FromStr,
{
    if let Ok(v) = env::var(key) {
        if let Ok(v) = v.parse::<T>() {
            return v;
        }
    }
    default
}

/// Reads a boolean option, accepting the spellings people actually use.
///
/// `bool::from_str` takes `true` and `false` and nothing else, so a `FOO=1`
/// reads as the default and says nothing about it. An option that is silently
/// ignored is worse than one that is missing.
pub fn get_env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

fn get_env_var_or_else<T, F>(key: &str, f: F) -> T
where
    T: FromStr,
    F: FnOnce() -> T,
{
    if let Ok(v) = env::var(key) {
        if let Ok(v) = v.parse::<T>() {
            return v;
        }
    }
    f()
}

#[cfg(target_os = "ios")]
lazy_static! {

    /// DNS cache size in the built-in DNS client.
    pub static ref DNS_CACHE_SIZE: usize = {
        get_env_var_or("DNS_CACHE_SIZE", 64)
    };
}

#[cfg(not(target_os = "ios"))]
lazy_static! {

    /// DNS cache size in the built-in DNS client.
    pub static ref DNS_CACHE_SIZE: usize = {
        get_env_var_or("DNS_CACHE_SIZE", 512)
    };
}

lazy_static! {

    // The purpose is not to propagate the header, but to extract the forwarded
    // source IP. Expects only comma separated IP list and only the first IP is
    // taken as the forwarded source. Having this value customizable would benefit
    // in case you don't trust the X-Forwarded-For header but there is another header
    // which you can trust, for example the CF-Connecting-IP provided by Cloudflare.
    pub static ref HTTP_FORWARDED_HEADER: String = {
        get_env_var_or("HTTP_FORWARDED_HEADER", "X-Forwarded-For".to_string())
    };

    /// Turn on TLS SNI sniffing, the sniffed SNI would override the original
    /// destination address, by default the sniffing would perform only on
    /// connections with destination port 443, set also TLS_DOMAIN_SNIFFING_ALL
    /// to make the sniffing work on all connections.
    pub static ref TLS_DOMAIN_SNIFFING: AtomicBool = {
        let v: bool = get_env_var_or_else(
            "TLS_DOMAIN_SNIFFING",
            || get_env_var_or("DOMAIN_SNIFFING", false), // deprecated env var
        );
        AtomicBool::new(v)
    };

    /// Turn on TLS SNI sniffing for all TCP connections, this may slow down the
    /// connections a little bit, depending on whether the sniff can make an early
    /// return.
    pub static ref TLS_DOMAIN_SNIFFING_ALL: AtomicBool = {
        let v: bool = get_env_var_or("TLS_DOMAIN_SNIFFING_ALL", false);
        AtomicBool::new(v)
    };

    /// Turn on HTTP host sniffing, by default only perform on connections with
    /// destination port 80.
    pub static ref HTTP_DOMAIN_SNIFFING: AtomicBool = {
        let v: bool = get_env_var_or("HTTP_DOMAIN_SNIFFING", false);
        AtomicBool::new(v)
    };

    /// Turn on HTTP host sniffing for all TCP connections, this may slow down the
    /// connections a little bit, depending on whether the sniff can make an early
    /// return.
    pub static ref HTTP_DOMAIN_SNIFFING_ALL: AtomicBool = {
        let v: bool = get_env_var_or("HTTP_DOMAIN_SNIFFING_ALL", false);
        AtomicBool::new(v)
    };

    /// Override the original destination with the sniffed domain.
    pub static ref DOMAIN_OVERRIDE: AtomicBool = {
        let v: bool = get_env_var_or("DOMAIN_OVERRIDE", false);
        AtomicBool::new(v)
    };

    /// Turn on DNS sniffing, if the destination is an IP, we try to find the
    /// domain from the DNS cache.
    pub static ref DNS_DOMAIN_SNIFFING: AtomicBool = {
        let v: bool = get_env_var_or("DNS_DOMAIN_SNIFFING", false);
        AtomicBool::new(v)
    };

    pub static ref API_LISTEN: String = {
        get_env_var_or("API_LISTEN", "".to_string())
    };

    pub static ref ENABLE_IPV6: bool = {
        get_env_var_or("ENABLE_IPV6", false)
    };

    pub static ref PREFER_IPV6: bool = {
        get_env_var_or("PREFER_IPV6", false)
    };

    pub static ref UNSPECIFIED_BIND_ADDR: SocketAddr = {
        get_env_var_or_else("UNSPECIFIED_BIND_ADDR", || {
            if *ENABLE_IPV6 {
                "[::]:0".to_string().parse().unwrap()
            } else {
                "0.0.0.0:0".to_string().parse().unwrap()
            }
        })
    };

    pub static ref GATEWAY_MODE: bool = {
        get_env_var_or("GATEWAY_MODE", false)
    };

    /// UDP session timeout. A UDP session shall be terminated if there are no
    /// activities in this period. The timeouts are observed only when a check
    /// is happened.
    pub static ref UDP_SESSION_TIMEOUT: u64 = {
        get_env_var_or("UDP_SESSION_TIMEOUT", 30)
    };

    /// Timeout for a DNS query for the built-in DNS client.
    pub static ref DNS_TIMEOUT: u64 = {
        get_env_var_or("DNS_TIMEOUT", 4)
    };

    pub static ref DEFAULT_TUN_NAME: String = {
        get_env_var_or("DEFAULT_TUN_NAME", "utun233".to_string())
    };

    pub static ref DEFAULT_TUN_IPV4_ADDR: String = {
        #[cfg(windows)]
        {
            get_env_var_or("DEFAULT_TUN_IPV4_ADDR", "10.7.7.2".to_string())
        }
        #[cfg(not(windows))]
        {
            get_env_var_or("DEFAULT_TUN_IPV4_ADDR", "192.168.233.2".to_string())
        }
    };

    pub static ref DEFAULT_TUN_IPV4_GW: String = {
        #[cfg(windows)]
        {
            get_env_var_or("DEFAULT_TUN_IPV4_GW", "10.7.7.1".to_string())
        }
        #[cfg(not(windows))]
        {
            get_env_var_or("DEFAULT_TUN_IPV4_GW", "192.168.233.1".to_string())
        }
    };

    pub static ref DEFAULT_TUN_IPV4_MASK: String = {
        get_env_var_or("DEFAULT_TUN_IPV4_MASK", "255.255.255.0".to_string())
    };

    pub static ref DEFAULT_TUN_IPV6_ADDR: String = {
        get_env_var_or("DEFAULT_TUN_IPV6_ADDR", "2001:2::2".to_string())
    };

    pub static ref DEFAULT_TUN_IPV6_GW: String = {
        get_env_var_or("DEFAULT_TUN_IPV6_GW", "2001:2::1".to_string())
    };

    pub static ref DEFAULT_TUN_IPV6_PREFIXLEN: i32 = {
        get_env_var_or("DEFAULT_TUN_IPV6_PREFIXLEN", 64)
    };
}
