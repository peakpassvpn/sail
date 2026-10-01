//! What a log or an error may tell of a URL: its scheme, host and port,
//! never its user, password, path or query, which carry a subscription's
//! token as often as not.

/// The host, and port, of `url`, with no user or password.
pub fn host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.rsplit('@').next().unwrap_or_default()
}

/// `url` as it may be told: `https://example.com:8443/…`, the `/…` there
/// when more was left out; what is no URL, `(a URL not shown)`.
pub fn url(url: &str) -> String {
    let scheme = url.split_once("://").map(|(scheme, _)| scheme).filter(|s| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    });
    let host = host(url);
    if scheme.is_none() || host.is_empty() {
        return "(a URL not shown)".to_string();
    }
    let rest = &url[url.find("://").map_or(0, |i| i + 3)..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let more = rest.len() > authority.len();
    format!(
        "{}://{}{}",
        scheme.unwrap_or_default(),
        host,
        if more { "/…" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_keeps_its_host_and_port_alone() {
        assert_eq!(
            url("https://user:pass@sub.example.com:8443/api/v1/client/subscribe?token=s3cret"),
            "https://sub.example.com:8443/…"
        );
        assert_eq!(url("http://example.com"), "http://example.com");
        assert_eq!(url("https://example.com/"), "https://example.com/…");
        assert_eq!(
            url("https://example.com?token=s3cret"),
            "https://example.com/…"
        );
        // What is no URL tells nothing.
        assert_eq!(url("s3cret"), "(a URL not shown)");
        assert_eq!(url("://s3cret"), "(a URL not shown)");
        assert_eq!(url("a b://s3cret/x"), "(a URL not shown)");
        assert_eq!(host("ftp://u:p@h.example:21/x"), "h.example:21");
    }
}
