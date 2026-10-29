use super::*;
use std::net::Ipv4Addr;

/// An admission whose free memory is what `free` holds, read at every
/// accept, keeping 100 bytes free.
fn admission(
    free: &Arc<AtomicU64>,
    descriptors: usize,
    stall: Duration,
    score: bool,
    events: &EventHub,
) -> Arc<Admission> {
    let free = free.clone();
    Arc::new(Admission::with(
        100,
        descriptors,
        stall,
        score,
        Box::new(move || Some(free.load(Ordering::Relaxed))),
        Duration::ZERO,
        events.clone(),
    ))
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

/// Pressure starts short of the reserve, and ends only past it and its
/// margin; under half of it, every new connection is refused; each change
/// is told once.
#[test]
fn pressure_follows_the_memory_with_a_margin() {
    let (free, events) = (Arc::new(AtomicU64::new(200)), EventHub::default());
    let mut changes = events.admission_changes();
    let a = admission(&free, 0, Duration::from_secs(3), false, &events);
    let level = |a: &Admission| a.info().level;

    assert!(a.check(ip(1)).is_ok());
    assert_eq!(level(&a), AdmissionLevel::Normal);
    free.store(90, Ordering::Relaxed);
    assert!(a.check(ip(1)).is_ok(), "pressure alone refuses no one");
    assert_eq!(level(&a), AdmissionLevel::Pressure);
    free.store(102, Ordering::Relaxed);
    a.check(ip(1)).unwrap();
    assert_eq!(level(&a), AdmissionLevel::Pressure, "within the margin");
    free.store(106, Ordering::Relaxed);
    a.check(ip(1)).unwrap();
    assert_eq!(level(&a), AdmissionLevel::Normal);
    free.store(40, Ordering::Relaxed);
    assert_eq!(a.check(ip(1)), Err(Refusal::Hard));
    assert_eq!(a.check(ip(2)), Err(Refusal::Hard));
    let info = a.info();
    assert_eq!((info.level, info.refused), (AdmissionLevel::Hard, 2));
    assert_eq!(info.free, Some(40));
    assert!(info.pressure > Duration::ZERO || info.level != AdmissionLevel::Normal);

    let told: Vec<_> = std::iter::from_fn(|| changes.try_recv().ok())
        .map(|c| c.level)
        .collect();
    assert_eq!(
        told,
        [
            AdmissionLevel::Pressure,
            AdmissionLevel::Normal,
            AdmissionLevel::Hard
        ]
    );
}

/// Under pressure, the handshakes in flight past the stall are closed,
/// oldest first; one that authenticated, or is younger, is not.
#[tokio::test]
async fn stalled_handshakes_are_evicted_under_pressure() {
    let (free, events) = (Arc::new(AtomicU64::new(200)), EventHub::default());
    let a = admission(&free, 0, Duration::from_millis(50), false, &events);
    let old = a.enter(ip(1));
    let mut authenticated = a.enter(ip(2));
    authenticated.succeeded();
    tokio::time::sleep(Duration::from_millis(60)).await;
    let young = a.enter(ip(3));

    // Not under pressure: nothing is closed.
    a.check(ip(4)).unwrap();
    assert!(
        futures::FutureExt::now_or_never(old.eviction().evicted()).is_none(),
        "evicted without pressure"
    );

    free.store(90, Ordering::Relaxed);
    a.check(ip(4)).unwrap();
    assert!(futures::FutureExt::now_or_never(old.eviction().evicted()).is_some());
    assert!(futures::FutureExt::now_or_never(authenticated.eviction().evicted()).is_none());
    assert!(futures::FutureExt::now_or_never(young.eviction().evicted()).is_none());
    assert_eq!(a.info().evicted, 1);
    assert_eq!(
        a.info().handshakes,
        2,
        "the authenticated one left the count"
    );
    drop((old, young, authenticated));
    assert_eq!(a.info().handshakes, 0);
}

/// An eviction wakes the connection waiting for it.
#[tokio::test]
async fn an_eviction_wakes_its_connection() {
    let (free, events) = (Arc::new(AtomicU64::new(200)), EventHub::default());
    let a = admission(&free, 0, Duration::ZERO, false, &events);
    let ticket = a.enter(ip(1));
    let waiting = tokio::spawn(ticket.eviction().evicted());
    tokio::task::yield_now().await;
    free.store(90, Ordering::Relaxed);
    a.check(ip(2)).unwrap();
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("woken")
        .unwrap();
}

/// Under pressure, a source whose handshakes mostly failed is refused; one
/// with as many successes, or too few to judge, is not; and without
/// pressure no source is.
#[test]
fn failing_sources_are_refused_under_pressure() {
    let (free, events) = (Arc::new(AtomicU64::new(200)), EventHub::default());
    let a = admission(&free, 0, Duration::from_secs(3), true, &events);
    for _ in 0..4 {
        drop(a.enter(ip(1)));
    }
    for ok in [true, false, true, false] {
        let mut ticket = a.enter(ip(2));
        if ok {
            ticket.succeeded();
        }
    }
    for _ in 0..3 {
        drop(a.enter(ip(3)));
    }
    assert!(a.check(ip(1)).is_ok(), "no pressure");
    free.store(90, Ordering::Relaxed);
    assert_eq!(a.check(ip(1)), Err(Refusal::Source));
    assert!(a.check(ip(2)).is_ok(), "as many successes as failures");
    assert!(a.check(ip(3)).is_ok(), "too few to judge");
    assert!(a.check(ip(4)).is_ok(), "unknown");
    assert_eq!(a.info().refused_sources, 1);

    // Without scoring, none is.
    let b = admission(&free, 0, Duration::from_secs(3), false, &events);
    for _ in 0..4 {
        drop(b.enter(ip(1)));
    }
    assert!(b.check(ip(1)).is_ok());
}

/// Handshakes past the descriptors' share are pressure, memory or not.
#[test]
fn too_many_handshakes_for_the_descriptors_are_pressure() {
    let events = EventHub::default();
    let a = Arc::new(Admission::with(
        0,
        2,
        Duration::from_secs(3),
        false,
        Box::new(|| panic!("memory is not looked at")),
        Duration::ZERO,
        events,
    ));
    let held: Vec<_> = (0..3).map(|n| a.enter(ip(n))).collect();
    a.check(ip(9)).unwrap();
    assert_eq!(a.info().level, AdmissionLevel::Pressure);
    drop(held);
    a.check(ip(9)).unwrap();
    assert_eq!(a.info().level, AdmissionLevel::Normal);
}

/// The memory is read at most every `READ_EVERY`, and only as connections
/// are accepted.
#[test]
fn the_memory_is_read_at_most_so_often() {
    let reads = Arc::new(AtomicUsize::new(0));
    let counted = reads.clone();
    let a = Admission::with(
        100,
        0,
        Duration::from_secs(3),
        false,
        Box::new(move || {
            counted.fetch_add(1, Ordering::Relaxed);
            Some(1000)
        }),
        READ_EVERY,
        EventHub::default(),
    );
    for _ in 0..100 {
        a.check(ip(1)).unwrap();
    }
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    std::thread::sleep(READ_EVERY + Duration::from_millis(20));
    a.check(ip(1)).unwrap();
    assert_eq!(reads.load(Ordering::Relaxed), 2);
}

/// No reserve and no descriptors' share: there is no admission to keep.
#[test]
fn off_by_default_on_a_client_and_on_on_a_server() {
    let options = crate::runtime::RuntimeOptions::default();
    assert!(Admission::new(&options.inbound, EventHub::default()).is_none());
    let server = crate::runtime::RuntimeOptions::profile(crate::runtime::Profile::Server);
    assert_eq!(server.inbound.memory_reserve, 20);
    assert_eq!(server.inbound.handshake_stall, Duration::from_secs(3));
    assert!(Admission::new(&server.inbound, EventHub::default()).is_some());
}
