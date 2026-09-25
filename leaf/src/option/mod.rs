use std::env;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;

use lazy_static::lazy_static;

// Gets an environment variable by a key and parses as type `T` or returns
// the provided default value.
fn get_env_var_or<T>(key: &str, default: T) -> T
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

// Sniffing becomes a route action (roadmap 0.2.4); until then these are the
// last options read from the environment.
lazy_static! {

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
}
