//! The group with members that are fakes: one refuses, one takes the
//! client's bytes and never answers, one answers each with its name.

use super::score::FIRST_BYTE_TIMEOUT;
use super::stream::MAX_REPLAY;
use super::*;
use crate::adapter::outbound::HandlerBuilder;
use crate::protocol::group::members::Member;
use crate::session::SocksAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy)]
enum Behaviour {
    Refuse,
    /// Takes the bytes, never answers.
    Blackhole,
    /// Answers each read with its name and what it read, after a delay.
    Answer(Duration),
    /// Answers once, then closes.
    AnswerOnce,
}

const ANSWER: Behaviour = Behaviour::Answer(Duration::ZERO);

/// A member that behaves as told, and keeps what each connection through
/// it received.
struct Fake {
    name: String,
    behaviour: Behaviour,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl OutboundStreamHandler for Fake {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        if let Behaviour::Refuse = self.behaviour {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"));
        }
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let received = self.received.clone();
        let at = {
            let mut r = lock(&received);
            r.push(Vec::new());
            r.len() - 1
        };
        let (delay, answers, once) = match self.behaviour {
            Behaviour::Blackhole => (Duration::ZERO, false, false),
            Behaviour::Answer(delay) => (delay, true, false),
            _ => (Duration::ZERO, true, true),
        };
        let name = self.name.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = server.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                lock(&received)[at].extend_from_slice(&buf[..n]);
                if !answers {
                    continue;
                }
                tokio::time::sleep(delay).await;
                let answer = format!("{}:{}", name, String::from_utf8_lossy(&buf[..n]));
                if server.write_all(answer.as_bytes()).await.is_err() || once {
                    break;
                }
            }
        });
        Ok(Box::new(client))
    }
}

struct Fakes {
    group: Arc<Group>,
    received: Vec<Arc<Mutex<Vec<Vec<u8>>>>>,
}

impl Fakes {
    /// What the connections through member `i` received, each.
    fn received(&self, i: usize) -> Vec<Vec<u8>> {
        lock(&self.received[i]).clone()
    }

    fn stats(&self, name: &str) -> MemberStats {
        lock(&self.group.stats)
            .get(&MemberKey::outbound(name))
            .cloned()
            .unwrap()
    }

    fn stats_or_none(&self, name: &str) -> Option<MemberStats> {
        lock(&self.group.stats)
            .get(&MemberKey::outbound(name))
            .cloned()
    }

    fn suspects(&self) -> Vec<String> {
        let mut s: Vec<String> = lock(&self.group.probes.suspects)
            .iter()
            .map(|k| k.name.to_string())
            .collect();
        s.sort();
        s
    }

    /// Makes `name` known, with `latency`.
    fn known(&self, name: &str, latency: u64) {
        self.group.with_stats(&MemberKey::outbound(name), |s| {
            s.answered(Duration::from_millis(latency), 1.0, Instant::now())
        });
    }
}

fn fake_member(name: &str, behaviour: Behaviour) -> (Member, Arc<Mutex<Vec<Vec<u8>>>>) {
    let received = Arc::new(Mutex::new(Vec::new()));
    let fake = Arc::new(Fake {
        name: name.to_string(),
        behaviour,
        received: received.clone(),
    });
    let handler = HandlerBuilder::default()
        .tag(name.to_string())
        .stream_handler(fake)
        .build();
    let member = Member {
        key: MemberKey::outbound(name),
        handler,
        kind: "",
    };
    (member, received)
}

fn group_of(members: Vec<Member>) -> Arc<Group> {
    let dns_client = crate::app::dns::DnsClient::new(
        &Default::default(),
        Arc::new(crate::net::DialDefaults::default()),
        &Default::default(),
    )
    .unwrap()
    .into_shared();
    Arc::new(Group {
        tag: "smart".to_string(),
        members: Members::of(members),
        dns_client,
        network: Default::default(),
        stats: Mutex::new(HashMap::new()),
        sites: Mutex::new(LruCache::with_expiry_duration_and_capacity(
            DEFAULT_SITE_TTL,
            16,
        )),
        priorities: vec![(
            crate::common::name_filter::NameFilter::new("^preferred").unwrap(),
            0.5,
        )],
        tolerance: Tolerance {
            ms: 30.0,
            ratio: 0.2,
        },
        timeout: DEFAULT_TIMEOUT,
        asn: None,
        interrupt: false,
        selected: Arc::new(Selection::new("", MemberKey::outbound(""))),
        latencies: MemberLatencies::default(),
        reported: Mutex::new(None),
        probes: Probes {
            interval: DEFAULT_INTERVAL,
            idle: DEFAULT_IDLE_TIMEOUT,
            last_used: Mutex::new(Instant::now()),
            wake: Notify::new(),
            forced: AtomicBool::new(false),
            suspects: Mutex::new(HashSet::new()),
            evaluated: watch::Sender::new(false),
            evaluate_before_use: false,
            task: Mutex::new(None),
        },
    })
}

fn fakes(members: &[(&str, Behaviour)]) -> Fakes {
    let (members, received): (Vec<Member>, Vec<_>) = members
        .iter()
        .map(|(name, behaviour)| fake_member(name, *behaviour))
        .unzip();
    Fakes {
        group: group_of(members),
        received,
    }
}

fn tls_session(domain: &str) -> Session {
    Session {
        destination: SocksAddr::Domain(domain.to_string(), 443),
        sniffed_protocol: Some(SniffedProtocol::Tls),
        ..Default::default()
    }
}

fn plain_session(domain: &str) -> Session {
    Session {
        destination: SocksAddr::Domain(domain.to_string(), 80),
        ..Default::default()
    }
}

async fn read_some(stream: &mut AnyStream) -> io::Result<String> {
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

#[tokio::test(start_paused = true)]
async fn a_member_that_fails_to_connect_is_passed_over_and_blamed() {
    let f = fakes(&[("a", Behaviour::Refuse), ("b", ANSWER)]);
    f.known("a", 10);
    f.known("b", 100);
    let mut s = stream::connect(f.group.clone(), &tls_session("example.com"))
        .await
        .unwrap();
    s.write_all(b"hello").await.unwrap();
    assert_eq!(read_some(&mut s).await.unwrap(), "b:hello");
    // b answered, so a is to blame.
    assert!(f.stats("a").is_failed(Instant::now()));
    assert!(!f.stats("b").is_failed(Instant::now()));
    assert!(f.suspects().is_empty());
}

#[tokio::test(start_paused = true)]
async fn when_every_member_fails_none_is_blamed_but_all_are_probed() {
    let f = fakes(&[("a", Behaviour::Refuse), ("b", Behaviour::Refuse)]);
    f.known("a", 10);
    f.known("b", 100);
    let result = stream::connect(f.group.clone(), &tls_session("example.com")).await;
    assert!(result.is_err());
    assert!(!f.stats("a").is_failed(Instant::now()));
    assert!(!f.stats("b").is_failed(Instant::now()));
    assert_eq!(f.suspects(), ["a", "b"]);
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_hello_goes_again_through_the_next_member() {
    let f = fakes(&[("a", Behaviour::Blackhole), ("b", ANSWER)]);
    f.known("a", 10);
    f.known("b", 100);
    let start = Instant::now();
    let mut s = stream::connect(f.group.clone(), &tls_session("example.com"))
        .await
        .unwrap();
    s.write_all(b"client").await.unwrap();
    s.write_all(b"hello").await.unwrap();
    let answer = read_some(&mut s).await.unwrap();
    assert!(
        start.elapsed() >= FIRST_BYTE_TIMEOUT,
        "{:?}",
        start.elapsed()
    );
    // b got both writes at once, and answered them.
    assert_eq!(answer, "b:clienthello");
    assert_eq!(f.received(0), [b"clienthello".to_vec()]);
    assert_eq!(f.received(1), [b"clienthello".to_vec()]);
    // The connection goes on through b.
    s.write_all(b"more").await.unwrap();
    assert_eq!(read_some(&mut s).await.unwrap(), "b:more");
    assert!(f.stats("a").is_failed(Instant::now()));
    // The site is b's from now on.
    let mut s = stream::connect(f.group.clone(), &tls_session("www.example.com"))
        .await
        .unwrap();
    s.write_all(b"again").await.unwrap();
    assert_eq!(read_some(&mut s).await.unwrap(), "b:again");
}

#[tokio::test(start_paused = true)]
async fn nothing_goes_again_once_bytes_reached_the_client() {
    let f = fakes(&[("a", Behaviour::AnswerOnce), ("b", ANSWER)]);
    f.known("a", 10);
    f.known("b", 100);
    let mut s = stream::connect(f.group.clone(), &tls_session("example.com"))
        .await
        .unwrap();
    s.write_all(b"hello").await.unwrap();
    assert_eq!(read_some(&mut s).await.unwrap(), "a:hello");
    let _ = s.write_all(b"more").await;
    // a closed: the client sees it, and b is never tried.
    assert_eq!(read_some(&mut s).await.unwrap(), "");
    assert!(f.received(1).is_empty());
    assert!(!f.stats("a").is_failed(Instant::now()));
}

#[tokio::test(start_paused = true)]
async fn nothing_goes_again_once_the_client_sent_too_much() {
    let f = fakes(&[("a", Behaviour::Blackhole), ("b", ANSWER)]);
    f.known("a", 10);
    f.known("b", 100);
    let mut s = stream::connect(f.group.clone(), &tls_session("example.com"))
        .await
        .unwrap();
    s.write_all(&vec![7u8; MAX_REPLAY + 1]).await.unwrap();
    let read = tokio::time::timeout(Duration::from_secs(60), read_some(&mut s)).await;
    assert!(read.is_err(), "still waiting on a");
    assert!(f.received(1).is_empty());
    drop(s);
    // a did not answer in time, but nothing else was tried to tell.
    assert!(!f.stats("a").is_failed(Instant::now()));
    assert_eq!(f.suspects(), ["a"]);
}

#[tokio::test(start_paused = true)]
async fn a_slow_plain_answer_is_no_failure() {
    let f = fakes(&[
        ("a", Behaviour::Answer(Duration::from_secs(20))),
        ("b", ANSWER),
    ]);
    f.known("a", 10);
    f.known("b", 100);
    let mut s = stream::connect(f.group.clone(), &plain_session("example.com"))
        .await
        .unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    assert!(read_some(&mut s).await.unwrap().starts_with("a:GET"));
    assert!(f.received(1).is_empty());
    let a = f.stats("a");
    assert!(!a.is_failed(Instant::now()));
    // Recorded, lightly: (10 + 20000 × 0.2) / 1.2.
    let latency = a.latency().unwrap();
    assert!(latency > 3000.0 && latency < 3500.0, "{}", latency);
}

#[tokio::test(start_paused = true)]
async fn a_failure_closes_no_other_connection() {
    let f = fakes(&[("a", ANSWER), ("b", ANSWER)]);
    f.known("a", 10);
    f.known("b", 100);
    let mut first = stream::connect(f.group.clone(), &tls_session("example.com"))
        .await
        .unwrap();
    first.write_all(b"one").await.unwrap();
    assert_eq!(read_some(&mut first).await.unwrap(), "a:one");
    // a fails another connection, and the group leaves it.
    f.group.blame(&[MemberKey::outbound("a")]);
    let mut second = stream::connect(f.group.clone(), &tls_session("other.org"))
        .await
        .unwrap();
    second.write_all(b"two").await.unwrap();
    assert_eq!(read_some(&mut second).await.unwrap(), "b:two");
    // The first connection carries on through a.
    first.write_all(b"three").await.unwrap();
    assert_eq!(read_some(&mut first).await.unwrap(), "a:three");
}

#[tokio::test(start_paused = true)]
async fn a_site_stays_on_its_member() {
    let f = fakes(&[("a", ANSWER), ("b", ANSWER), ("c", ANSWER)]);
    f.known("a", 100);
    f.known("b", 105);
    f.known("c", 110);
    let mut reached = Vec::new();
    for host in ["www.example.com", "api.example.com", "example.com"] {
        for _ in 0..5 {
            let mut s = stream::connect(f.group.clone(), &tls_session(host))
                .await
                .unwrap();
            s.write_all(b"x").await.unwrap();
            let answer = read_some(&mut s).await.unwrap();
            reached.push(answer[..1].to_string());
        }
    }
    reached.dedup();
    assert_eq!(reached.len(), 1, "{:?}", reached);
}

#[tokio::test(start_paused = true)]
async fn the_priority_steers_the_choice() {
    let f = fakes(&[("plain", ANSWER), ("preferred", ANSWER)]);
    // 180 × 0.5 is 90: plain, at 200, is beyond the tolerance of it.
    f.known("plain", 200);
    f.known("preferred", 180);
    for i in 0..10 {
        let sess = tls_session(&format!("s{}.org", i));
        let mut s = stream::connect(f.group.clone(), &sess).await.unwrap();
        s.write_all(b"x").await.unwrap();
        assert!(read_some(&mut s).await.unwrap().starts_with("preferred"));
    }
}

#[tokio::test(start_paused = true)]
async fn a_member_gone_takes_its_state_and_a_new_one_is_unknown() {
    let (a, _) = fake_member("a", ANSWER);
    let (b, _) = fake_member("b", ANSWER);
    let (c, _) = fake_member("c", ANSWER);
    let group = group_of(vec![a.clone(), b]);
    let f = Fakes {
        group: group.clone(),
        received: Vec::new(),
    };
    f.known("a", 10);
    f.known("b", 20);
    group.members.publish(vec![a, c]);
    let snapshot = group.members.load();
    group.merged(&snapshot, true);
    assert!(!lock(&group.stats).contains_key(&MemberKey::outbound("b")));
    // c is tried after the known, until measured.
    assert_eq!(group.plan(&snapshot, "example.com"), [0, 1]);
    assert_eq!(f.stats("c").score(Instant::now()), None);
    group.probed(&snapshot, &[1], &[Some(Duration::from_millis(5))]);
    assert_eq!(f.stats("c").score(Instant::now()), Some(5.0));
    // Nothing to probe of members known lately.
    assert!(group.to_probe(&snapshot).is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_member_shown_is_the_one_used_most() {
    let f = fakes(&[("a", ANSWER), ("b", ANSWER)]);
    let now = Instant::now();
    for (name, uses) in [("a", 1), ("b", 3)] {
        for _ in 0..uses {
            f.group
                .with_stats(&MemberKey::outbound(name), |s| s.used(now));
        }
    }
    f.known("a", 10);
    f.group.report_now(now);
    assert_eq!(f.group.selected.get().name.as_ref(), "b");
    let latencies = f.group.latencies.read(|l| l.clone());
    assert_eq!(
        latencies[&MemberKey::outbound("a")].latency,
        Some(Duration::from_millis(10))
    );
    assert!(!latencies.contains_key(&MemberKey::outbound("c")));
}

#[tokio::test(start_paused = true)]
async fn probes_go_to_stale_and_failed_members_twelve_at_most() {
    let members: Vec<Member> = (0..20)
        .map(|i| fake_member(&format!("m{}", i), ANSWER).0)
        .collect();
    let group = group_of(members);
    let snapshot = group.members.load();
    let f = Fakes {
        group: group.clone(),
        received: Vec::new(),
    };
    assert_eq!(group.to_probe(&snapshot).len(), MAX_PROBED);
    // Known lately: only the failed, and the suspected, are probed.
    for i in 0..20 {
        f.known(&format!("m{}", i), 10);
    }
    assert!(group.to_probe(&snapshot).is_empty());
    group.blame(&[MemberKey::outbound("m3")]);
    assert_eq!(group.to_probe(&snapshot), [3]);
    group.suspect(&[MemberKey::outbound("m5")]);
    assert_eq!(group.to_probe(&snapshot), [3, 5]);
    // Of many stale ones, the most used, then those probed longest ago.
    tokio::time::advance(DEFAULT_INTERVAL + Duration::from_secs(60)).await;
    let now = Instant::now();
    for i in 0..20u64 {
        group.with_stats(&MemberKey::outbound(&format!("m{}", i)), |s| {
            for _ in 0..i {
                s.used(now);
            }
            s.last_probed = Some(now - DEFAULT_INTERVAL - Duration::from_secs(i));
        });
    }
    let mut picked = group.to_probe(&snapshot);
    picked.sort();
    // m14 to m19 by use, then the six of the rest probed longest ago.
    assert_eq!(picked, [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
}

#[test]
fn policy_priority_takes_mihomo_filters_lookarounds_included() {
    let filter = crate::common::name_filter::NameFilter::new("^(?!.*Ukraine).*HK").unwrap();
    let mut warnings = Vec::new();
    assert!(filter.matches("HK 01", &mut warnings));
    assert!(!filter.matches("HK Ukraine", &mut warnings));
    assert!(warnings.is_empty());
}

fn on(interface: &str) -> crate::net::network::NetworkState {
    crate::net::network::NetworkState {
        interface: Some(interface.into()),
        ..Default::default()
    }
}

#[tokio::test(start_paused = true)]
async fn a_change_of_network_forgets_what_was_of_the_one_before() {
    use crate::net::network::{ChangeReason, NetworkState};
    let f = fakes(&[("a", ANSWER), ("b", ANSWER)]);
    let a = MemberKey::outbound("a");
    let b = MemberKey::outbound("b");
    let learn = || {
        f.known("a", 10);
        f.known("b", 100);
        f.group.blame(std::slice::from_ref(&a));
        f.group
            .with_site("example.com", |s| s.connected(&b, Instant::now()));
    };
    learn();
    f.group.network.detected(on("en0"), ChangeReason::State);
    f.group
        .network
        .detected(NetworkState::default(), ChangeReason::State);
    // Down: nothing is learnt of no network, and nothing forgotten.
    f.group.network_changed();
    assert!(f.stats("a").is_failed(Instant::now()));
    assert!(!lock(&f.group.sites).is_empty());
    assert!(f.suspects().is_empty());

    f.group.network.detected(on("en1"), ChangeReason::State);
    f.group.network_changed();
    f.group.network_changed();
    assert!(lock(&f.group.sites).is_empty());
    assert!(!f.stats("a").is_failed(Instant::now()));
    // The latencies stay, until new samples replace them.
    assert_eq!(f.stats("a").latency(), Some(10.0));
    assert_eq!(f.stats("b").latency(), Some(100.0));
    assert_eq!(f.suspects(), ["a", "b"]);
    assert_eq!(f.group.to_probe(&f.group.members.load()), [0, 1]);
}

#[tokio::test(start_paused = true)]
async fn probes_pause_while_the_network_is_down() {
    use crate::net::network::{ChangeReason, NetworkState};
    let f = fakes(&[("a", ANSWER)]);
    let network = &f.group.network;
    network.detected(on("en0"), ChangeReason::State);
    network.detected(NetworkState::default(), ChangeReason::State);
    let probe = HttpProbe::new(
        "http://example.com/",
        f.group.dns_client.clone(),
        &Default::default(),
    )
    .unwrap();
    tokio::spawn(probe_loop(Arc::downgrade(&f.group), probe));
    // Between two ticks: only the change can probe before the next.
    tokio::time::sleep(DEFAULT_INTERVAL * 3 + Duration::from_secs(30)).await;
    assert_eq!(f.stats_or_none("a").and_then(|s| s.last_probed), None);

    // Back: every member is probed at once.
    network.detected(on("en0"), ChangeReason::State);
    f.group.network_changed();
    tokio::time::sleep(DEFAULT_TIMEOUT + Duration::from_secs(1)).await;
    assert!(f.stats("a").last_probed.is_some());
}
