//! The site a domain belongs to, which the groups that keep a site on one
//! member (load-balance's consistent hashing, smart) go by.

/// The registrable domain of `domain` by the public suffix list: its
/// public suffix and the label before it (`bbc.co.uk`, `alice.github.io`).
/// A name that is a public suffix itself, or has a single label, is its
/// own key.
#[cfg(feature = "load-balance-psl")]
pub fn registrable_domain(domain: &str) -> String {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    match psl::domain_str(&domain) {
        Some(registrable) => registrable.to_owned(),
        None => domain,
    }
}

/// The registrable domain of `domain`, approximately, without the public
/// suffix list (the `load-balance-psl` feature): the last two labels, or
/// three under a two-letter country code with a common second level
/// (`example.co.uk`). The users of a shared suffix such as `github.io`
/// go together.
#[cfg(not(feature = "load-balance-psl"))]
pub fn registrable_domain(domain: &str) -> String {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return domain;
    }
    const SECOND_LEVELS: &[&str] = &["co", "com", "net", "org", "gov", "edu", "ac", "ne", "or"];
    let keep = if labels[n - 1].len() == 2 && SECOND_LEVELS.contains(&labels[n - 2]) {
        3
    } else {
        2
    };
    labels[n - keep..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What either way of finding the registrable domain gives.
    #[test]
    fn registrable_domains() {
        for (domain, registrable) in [
            ("www.example.com", "example.com"),
            ("a.b.example.com.", "example.com"),
            ("WWW.Example.COM", "example.com"),
            ("example.com", "example.com"),
            ("news.bbc.co.uk", "bbc.co.uk"),
            ("bbc.co.uk", "bbc.co.uk"),
            ("co.uk", "co.uk"),
            ("github.io", "github.io"),
            ("blogspot.com", "blogspot.com"),
            // Single labels, and names under no known suffix.
            ("localhost", "localhost"),
            ("intranet.", "intranet"),
            ("printer.lan", "printer.lan"),
            ("a.printer.lan", "printer.lan"),
        ] {
            assert_eq!(registrable_domain(domain), registrable, "{}", domain);
        }
    }

    /// Suffixes only the list knows: each user of a shared suffix is a
    /// site of its own.
    #[cfg(feature = "load-balance-psl")]
    #[test]
    fn registrable_domains_by_the_list() {
        for (domain, registrable) in [
            ("www.city.kawasaki.jp", "city.kawasaki.jp"),
            ("alice.github.io", "alice.github.io"),
            ("x.alice.github.io", "alice.github.io"),
            ("myblog.blogspot.com", "myblog.blogspot.com"),
            ("www.myblog.blogspot.com", "myblog.blogspot.com"),
            ("shop.example.com.au", "example.com.au"),
        ] {
            assert_eq!(registrable_domain(domain), registrable, "{}", domain);
        }
    }

    /// Without the list, the users of a shared suffix go together.
    #[cfg(not(feature = "load-balance-psl"))]
    #[test]
    fn registrable_domains_approximately() {
        for (domain, registrable) in [
            ("alice.github.io", "github.io"),
            ("myblog.blogspot.com", "blogspot.com"),
            ("shop.example.com.au", "example.com.au"),
        ] {
            assert_eq!(registrable_domain(domain), registrable, "{}", domain);
        }
    }
}
