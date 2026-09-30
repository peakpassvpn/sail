//! Connecting to one of several addresses: one by one, or racing the two
//! families (Happy Eyeballs), as sing-box does (`DialSerial` and
//! `DialParallel` of sing's `common/network/multi.go`).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// How the addresses of one destination are tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Order {
    /// Whether the families race; one by one, in the order given, if not.
    pub race: bool,
    /// Whether IPv6's addresses go first in the race; IPv4's do otherwise.
    pub prefer_ipv6: bool,
    /// How long the first family has before the other joins the race.
    pub fallback_delay: Duration,
}

/// Connects to one of `addrs` with `connect`, as `order` says.
///
/// Racing, the addresses of the family that goes first are tried one by
/// one; the other family's are tried one by one too, from
/// `fallback_delay` on, or at once when the first family's have all
/// failed. The first connection made wins, and the other attempt is
/// dropped, closing what it made. With addresses of one family only, or
/// not racing, they are tried one by one in the order given. When all
/// fail, the error is the first family's.
pub async fn connect<T, F, Fut>(addrs: &[SocketAddr], order: Order, connect: F) -> io::Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let is_v4 = |a: &&SocketAddr| match a {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(a) => a.ip().to_ipv4_mapped().is_some(),
    };
    let v4: Vec<SocketAddr> = addrs.iter().filter(is_v4).copied().collect();
    let v6: Vec<SocketAddr> = addrs.iter().filter(|a| !is_v4(a)).copied().collect();
    if !order.race || v4.is_empty() || v6.is_empty() {
        return serial(addrs, &connect).await;
    }
    let (primaries, fallbacks) = if order.prefer_ipv6 {
        (v6, v4)
    } else {
        (v4, v6)
    };
    let primary = serial(&primaries, &connect);
    let fallback = serial(&fallbacks, &connect);
    let delay = tokio::time::sleep(order.fallback_delay);
    tokio::pin!(primary, fallback, delay);
    let mut primary_error: Option<io::Error> = None;
    let mut fallback_error: Option<io::Error> = None;
    let mut fallback_started = false;
    loop {
        tokio::select! {
            r = &mut primary, if primary_error.is_none() => match r {
                Ok(c) => return Ok(c),
                Err(e) => {
                    if fallback_error.is_some() {
                        return Err(e);
                    }
                    primary_error = Some(e);
                    fallback_started = true;
                }
            },
            () = &mut delay, if !fallback_started => fallback_started = true,
            r = &mut fallback, if fallback_started && fallback_error.is_none() => match r {
                Ok(c) => return Ok(c),
                Err(e) => match primary_error.take() {
                    Some(primary) => return Err(primary),
                    None => fallback_error = Some(e),
                },
            },
        }
    }
}

/// Tries `addrs` one by one; failing, says why each failed.
async fn serial<T, F, Fut>(addrs: &[SocketAddr], connect: &F) -> io::Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut errors: Vec<(SocketAddr, io::Error)> = Vec::new();
    for addr in addrs {
        match connect(*addr).await {
            Ok(c) => return Ok(c),
            Err(e) => errors.push((*addr, e)),
        }
    }
    Err(match errors.len() {
        0 => io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to"),
        1 => errors.pop().map(|(_, e)| e).expect("one error"),
        _ => {
            // The kind of the last, and each address's error.
            let kind = errors.last().map(|(_, e)| e.kind()).expect("errors");
            let each = errors
                .iter()
                .map(|(addr, e)| format!("{}: {}", addr, e))
                .collect::<Vec<_>>()
                .join("; ");
            io::Error::new(kind, format!("all attempts failed: {}", each))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Instant};

    const V4: &str = "192.0.2.1:443";
    const V4B: &str = "192.0.2.2:443";
    const V6: &str = "[2001:db8::1]:443";

    fn addrs(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    fn racing(prefer_ipv6: bool) -> Order {
        Order {
            race: true,
            prefer_ipv6,
            fallback_delay: Duration::from_millis(300),
        }
    }

    /// An address that is never answered, until a connect timeout of 5s,
    /// and one that answers at once.
    async fn blackholed_v6(addr: SocketAddr) -> io::Result<SocketAddr> {
        if addr.is_ipv6() {
            sleep(Duration::from_secs(5)).await;
            return Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"));
        }
        Ok(addr)
    }

    #[tokio::test(start_paused = true)]
    async fn ipv4_wins_300ms_after_a_blackholed_ipv6() {
        let start = Instant::now();
        let won = connect(&addrs(&[V6, V4]), racing(true), blackholed_v6)
            .await
            .unwrap();
        assert_eq!(won, V4.parse().unwrap());
        assert_eq!(start.elapsed(), Duration::from_millis(300));
    }

    #[tokio::test(start_paused = true)]
    async fn ipv4_goes_first_unless_ipv6_is_preferred() {
        let start = Instant::now();
        let won = connect(&addrs(&[V6, V4]), racing(false), blackholed_v6)
            .await
            .unwrap();
        assert_eq!(won, V4.parse().unwrap());
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn the_other_family_starts_at_once_when_the_first_fails() {
        let start = Instant::now();
        let refused_v6 = |addr: SocketAddr| async move {
            if addr.is_ipv6() {
                sleep(Duration::from_millis(50)).await;
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            sleep(Duration::from_millis(10)).await;
            Ok(addr)
        };
        let won = connect(&addrs(&[V6, V4]), racing(true), refused_v6)
            .await
            .unwrap();
        assert_eq!(won, V4.parse().unwrap());
        assert_eq!(start.elapsed(), Duration::from_millis(60));
    }

    #[tokio::test(start_paused = true)]
    async fn both_failing_gives_the_first_family_s_error() {
        let failing = |addr: SocketAddr| async move {
            if addr.is_ipv6() {
                sleep(Duration::from_secs(1)).await;
                Err::<(), _>(io::Error::new(io::ErrorKind::TimedOut, "v6 timed out"))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "v4 refused",
                ))
            }
        };
        let e = connect(&addrs(&[V6, V4]), racing(true), failing)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(e.to_string(), "v6 timed out");
        // Several of one family: each is named.
        let e = connect(&addrs(&[V4, V4B]), racing(false), failing)
            .await
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            "all attempts failed: 192.0.2.1:443: v4 refused; 192.0.2.2:443: v4 refused"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn not_racing_it_tries_them_in_turn() {
        // As with TCP Fast Open: the blackholed address first holds up the
        // other for its whole timeout.
        let start = Instant::now();
        let order = Order {
            race: false,
            ..racing(true)
        };
        let won = connect(&addrs(&[V6, V4]), order, blackholed_v6)
            .await
            .unwrap();
        assert_eq!(won, V4.parse().unwrap());
        assert_eq!(start.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn one_family_is_tried_in_turn() {
        let start = Instant::now();
        let slow_first = |addr: SocketAddr| async move {
            if addr == V4.parse().unwrap() {
                sleep(Duration::from_secs(5)).await;
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            Ok(addr)
        };
        let won = connect(&addrs(&[V4, V4B]), racing(false), slow_first)
            .await
            .unwrap();
        assert_eq!(won, V4B.parse().unwrap());
        assert_eq!(start.elapsed(), Duration::from_secs(5));
    }

    /// The loser's connection, made after the race is won, is closed: its
    /// attempt is dropped.
    #[tokio::test(start_paused = true)]
    async fn the_loser_is_dropped() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let finished = Arc::new(AtomicUsize::new(0));
        let slow = {
            let finished = finished.clone();
            move |addr: SocketAddr| {
                let finished = finished.clone();
                async move {
                    let wait = if addr.is_ipv6() { 1000 } else { 400 };
                    sleep(Duration::from_millis(wait)).await;
                    finished.fetch_add(1, Ordering::SeqCst);
                    Ok(addr)
                }
            }
        };
        let won = connect(&addrs(&[V6, V4]), racing(true), slow)
            .await
            .unwrap();
        // IPv4 started at 300ms and answered at 700ms, before IPv6.
        assert_eq!(won, V4.parse().unwrap());
        sleep(Duration::from_secs(2)).await;
        assert_eq!(finished.load(Ordering::SeqCst), 1);
    }
}
