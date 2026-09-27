//! The host of an HTTP/1 request.

use super::{is_domain_name, Sniff, MAX_SNIFF_LEN};

/// Header lines looked through for the host.
const MAX_HEADERS: usize = 100;

/// Whether `c` may be in a method or a header name: an RFC 9110 token.
fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// The first bytes of a connection: an HTTP/1 request line and headers, up
/// to the host. The host comes from an absolute request target, from the
/// target of CONNECT, or else from the Host header, as Go's
/// `http.ReadRequest` takes it, without the port.
pub fn sniff(buf: &[u8]) -> Sniff {
    let buf = &buf[..buf.len().min(MAX_SNIFF_LEN)];
    let mut lines = buf.split_inclusive(|c| *c == b'\n');
    let Some(line) = lines.next() else {
        return Sniff::NeedMore;
    };
    let Some(line) = line.strip_suffix(b"\n") else {
        return if request_line_prefix(line) {
            Sniff::NeedMore
        } else {
            Sniff::NotMatch
        };
    };
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Some((method, target)) = request_line(line) else {
        return Sniff::NotMatch;
    };
    if method == b"CONNECT" {
        return found(target);
    }
    if let Some(authority) = absolute_authority(target) {
        return found(authority);
    }
    for (i, line) in lines.enumerate() {
        if i >= MAX_HEADERS {
            return Sniff::NotMatch;
        }
        let Some(line) = line.strip_suffix(b"\n") else {
            return Sniff::NeedMore;
        };
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            // The end of the headers, without a Host.
            return Sniff::Found(None);
        }
        // A folded line continues the header before it.
        if line[0] == b' ' || line[0] == b'\t' {
            continue;
        }
        let Some(colon) = line.iter().position(|c| *c == b':') else {
            return Sniff::NotMatch;
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.is_empty() || !name.iter().all(|c| is_tchar(*c)) {
            return Sniff::NotMatch;
        }
        if name.eq_ignore_ascii_case(b"host") {
            return found(value.trim_ascii());
        }
    }
    Sniff::NeedMore
}

/// Whether `line`, a request line cut short, may yet become one.
fn request_line_prefix(line: &[u8]) -> bool {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.splitn(3, |c| *c == b' ');
    let method = parts.next().unwrap_or_default();
    if method.len() > 32 || !method.iter().all(|c| is_tchar(*c)) {
        return false;
    }
    let Some(target) = parts.next() else {
        return true;
    };
    if method.is_empty() || !target.iter().all(|c| c.is_ascii_graphic()) {
        return false;
    }
    let Some(version) = parts.next() else {
        return true;
    };
    !target.is_empty()
        && version.len() <= 8
        && version.iter().enumerate().all(|(i, c)| match i {
            0..=4 => *c == b"HTTP/"[i],
            6 => *c == b'.',
            _ => c.is_ascii_digit(),
        })
}

/// The method and the target of a request line.
fn request_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut parts = line.splitn(3, |c| *c == b' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if method.is_empty() || method.len() > 32 || !method.iter().all(|c| is_tchar(*c)) {
        return None;
    }
    if target.is_empty() || !target.iter().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    // HTTP/x.y, as Go's ParseHTTPVersion takes it.
    match version {
        [b'H', b'T', b'T', b'P', b'/', major, b'.', minor]
            if major.is_ascii_digit() && minor.is_ascii_digit() =>
        {
            Some((method, target))
        }
        _ => None,
    }
}

/// The authority of an absolute request target, as a proxy is asked.
fn absolute_authority(target: &[u8]) -> Option<&[u8]> {
    let scheme_end = target.windows(3).position(|w| w == b"://")?;
    let scheme = &target[..scheme_end];
    if scheme.is_empty() || !scheme.iter().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let rest = &target[scheme_end + 3..];
    let end = rest
        .iter()
        .position(|c| matches!(c, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    // Without the user information.
    Some(match authority.iter().rposition(|c| *c == b'@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    })
}

/// The request found, naming the host of `authority` if it is a domain.
fn found(authority: &[u8]) -> Sniff {
    Sniff::Found(
        std::str::from_utf8(host_of(authority))
            .ok()
            .filter(|h| is_domain_name(h))
            .map(String::from),
    )
}

/// The host of `host[:port]`, or of `[address]:port`.
fn host_of(authority: &[u8]) -> &[u8] {
    if let Some(rest) = authority.strip_prefix(b"[") {
        return match rest.iter().position(|c| *c == b']') {
            Some(end) => &rest[..end],
            None => authority,
        };
    }
    match authority.iter().rposition(|c| *c == b':') {
        Some(colon) if authority[colon + 1..].iter().all(u8::is_ascii_digit) => &authority[..colon],
        _ => authority,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(name: &str) -> Sniff {
        Sniff::Found(Some(name.to_string()))
    }

    #[test]
    fn the_host_header() {
        let request = b"GET /index.html HTTP/1.1\r\nUser-Agent: curl/8\r\nHost: Example.com:8080\r\nAccept: */*\r\n\r\n";
        assert_eq!(sniff(request), found("Example.com"));
        let host_line = request.len() - b"Accept: */*\r\n\r\n".len();
        for len in 0..host_line {
            assert_eq!(sniff(&request[..len]), Sniff::NeedMore, "{}", len);
        }
        assert_eq!(
            sniff(b"POST / HTTP/1.0\nhost:  example.com \n\n"),
            found("example.com")
        );
    }

    #[test]
    fn the_host_of_a_proxy_request() {
        assert_eq!(
            sniff(b"GET http://user@example.com:80/a?b HTTP/1.1\r\nHost: other.com\r\n\r\n"),
            found("example.com")
        );
        assert_eq!(
            sniff(b"CONNECT example.com:443 HTTP/1.1\r\n"),
            found("example.com")
        );
    }

    #[test]
    fn a_request_without_a_domain_is_still_http() {
        assert_eq!(sniff(b"GET / HTTP/1.1\r\n\r\n"), Sniff::Found(None));
        assert_eq!(
            sniff(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n"),
            Sniff::Found(None)
        );
        assert_eq!(
            sniff(b"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n"),
            Sniff::Found(None)
        );
    }

    #[test]
    fn what_is_not_a_request() {
        for bytes in [
            &b"\x16\x03\x01\x02\x00"[..],
            b"SSH-2.0-OpenSSH_9.6\r\n",
            b"GET /\r\n",
            b"GET / HTTP/1.1 extra\r\n",
            b"GET / HTTX",
            b"GET / HTTP/1.10",
            b"GET  / HTTP/1.1\r\n",
            b"GET / HTTP/1.1\r\nno colon\r\n",
            b"GET / HTTP/1.1\r\nbad name: x\r\n",
            b"\r\n",
        ] {
            assert_eq!(sniff(bytes), Sniff::NotMatch, "{:?}", bytes);
        }
        let mut many = b"GET / HTTP/1.1\r\n".to_vec();
        for _ in 0..=MAX_HEADERS {
            many.extend_from_slice(b"X: y\r\n");
        }
        assert_eq!(sniff(&many), Sniff::NotMatch);
    }
}
