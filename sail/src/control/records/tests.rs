use super::*;
use crate::control::events::{End, Outcome, RecordKind};
use crate::session::{Network, SocksAddr};
use std::time::Duration;

fn record(id: u64, up: u64, closed: bool) -> Arc<ConnectionRecord> {
    let at = std::time::UNIX_EPOCH + Duration::from_secs(1000 + id);
    Arc::new(ConnectionRecord {
        id,
        parent_id: None,
        run: std::time::UNIX_EPOCH,
        seq: 0,
        kind: match closed {
            true => RecordKind::Closed(End::Finished),
            false => RecordKind::Interim,
        },
        outcome: closed.then_some(Outcome::Ok),
        reason: None,
        network: Network::Tcp,
        user: Some("a".into()),
        inbound: "in".into(),
        source: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:2".parse().unwrap(),
        destination: SocksAddr::any(),
        request_destination: None,
        domain: None,
        domain_source: None,
        outbound: Some("g".into()),
        chain: vec!["g".into(), "out".into()],
        up_total: up,
        down_total: up * 10,
        start: at,
        at,
    })
}

fn drain(reader: &mut RecordStream) -> Vec<u64> {
    std::iter::from_fn(|| reader.try_next())
        .map(|r| r.id)
        .collect()
}

/// Past the cap every closed record is still kept, in order; interim
/// records of a timed pass are dropped and counted, and those of a pass
/// the host asked for kept.
#[test]
fn closed_records_are_kept_past_the_cap_and_only_interim_ones_dropped() {
    let sink = LosslessRecords::new(2);
    let mut reader = sink.reader().unwrap();
    sink.push(record(1, 1, false), true);
    sink.push(record(2, 2, true), true);
    // Full: a timed interim record goes, a closed one and an asked one stay.
    sink.push(record(3, 4, false), true);
    sink.push(record(4, 8, true), true);
    sink.push(record(5, 16, false), false);
    assert_eq!((reader.queued(), reader.dropped()), (4, 1));
    assert_eq!(drain(&mut reader), [1, 2, 4, 5]);
    // Drained: an interim record is queued again.
    sink.push(record(6, 32, false), true);
    assert_eq!(drain(&mut reader), [6]);
    assert_eq!(reader.dropped(), 1);
}

/// While `cap` closed records wait, new connections are refused and
/// counted; once the reader takes one, they are let in again. Interim
/// records waiting do not refuse anyone.
#[test]
fn closed_records_at_the_cap_refuse_new_connections_until_read() {
    let sink = LosslessRecords::new(2);
    let mut reader = sink.reader().unwrap();
    sink.push(record(1, 1, false), false);
    sink.push(record(2, 1, false), false);
    sink.push(record(3, 1, true), true);
    assert!(!sink.refuse());
    sink.push(record(4, 1, true), true);
    assert!(sink.refuse());
    assert!(sink.refuse());
    assert_eq!(reader.refused(), 2);
    // The interim records go first: still refused.
    assert_eq!(reader.try_next().unwrap().id, 1);
    assert_eq!(reader.try_next().unwrap().id, 2);
    assert!(sink.refuse());
    assert_eq!(reader.try_next().unwrap().id, 3);
    assert!(!sink.refuse());
    assert_eq!(reader.refused(), 3);
}

/// One reader at a time; another once it is dropped.
#[test]
fn one_reader_at_a_time() {
    let sink = LosslessRecords::new(4);
    let reader = sink.reader().unwrap();
    assert!(sink.reader().is_none());
    drop(reader);
    assert!(sink.reader().is_some());
}

/// A reader waiting is woken by a record.
#[tokio::test]
async fn a_waiting_reader_is_woken() {
    let sink = LosslessRecords::new(4);
    let mut reader = sink.reader().unwrap();
    let waiting = tokio::spawn(async move { reader.next().await });
    tokio::task::yield_now().await;
    sink.push(record(1, 1, true), true);
    let got = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.id, 1);
}

#[test]
fn an_envelope_owns_its_binding_until_the_reader_finishes_with_it() {
    use crate::control::context::ContextPool;
    let pool = ContextPool::new(1);
    let context = pool.bind(|| String::from("private binding")).unwrap();
    let sink = LosslessRecords::new(1);
    let mut reader = sink.reader().unwrap();
    let closed = record(1, 4, true);
    sink.push_envelope(
        RecordEnvelope {
            record: closed.clone(),
            context: Some(context),
        },
        false,
    );
    assert!(pool.bind(|| ()).is_none(), "queue owns the binding");
    let envelope = reader.try_next_envelope().unwrap();
    assert!(Arc::ptr_eq(&envelope.record, &closed));
    assert_eq!(
        envelope.context.as_ref().unwrap().get::<String>().unwrap(),
        "private binding"
    );
    assert!(reader.try_next_envelope().is_none());
    assert!(!sink.refuse(), "queue gate reopens when the record is read");
    assert!(
        pool.bind(|| ()).is_none(),
        "reader batch is still in flight"
    );
    let copy = envelope.clone();
    drop(envelope);
    assert!(
        pool.bind(|| ()).is_none(),
        "failed spool handoff may retain an envelope"
    );
    drop(copy);
    assert!(pool.bind(|| ()).is_some(), "last owner releases the slot");
}

fn capture_logs<T>(f: impl FnOnce() -> T) -> (T, Vec<(tracing::Level, String)>) {
    use tracing_subscriber::layer::SubscriberExt;

    struct Message(String);
    impl tracing::field::Visit for Message {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.0.push_str(value);
            }
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                use std::fmt::Write;
                let _ = write!(&mut self.0, "{value:?}");
            }
        }
    }

    struct Collect(Arc<Mutex<Vec<(tracing::Level, String)>>>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Collect {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let meta = event.metadata();
            if *meta.level() > tracing::Level::INFO
                || !meta.target().starts_with("sail::control::records")
            {
                return;
            }
            let mut msg = Message(String::new());
            event.record(&mut msg);
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((*meta.level(), msg.0));
        }
    }

    let kept = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(Collect(kept.clone()));
    let out = tracing::subscriber::with_default(subscriber, f);
    let lines = std::mem::take(&mut *kept.lock().unwrap_or_else(|e| e.into_inner()));
    (out, lines)
}

#[test]
fn refusals_warn_at_once_and_every_window_past_large_counts() {
    use portable_atomic::{AtomicU64, Ordering as AtomicOrdering};

    let base = Instant::now();
    let elapsed_ms = Arc::new(AtomicU64::new(0));
    let sink = {
        let elapsed_ms = elapsed_ms.clone();
        LosslessRecords::with_clock(4, move || {
            base + Duration::from_millis(elapsed_ms.load(AtomicOrdering::Relaxed))
        })
    };
    let mut reader = sink.reader().unwrap();

    // Reaching `cap` and draining without refusing any connection stays silent.
    for id in 1..=4 {
        sink.push(record(id, 1, true), true);
    }
    let (_, silent) = capture_logs(|| while reader.try_next().is_some() {});
    assert!(silent.is_empty(), "{silent:?}");

    // Fill `cap` closed records plus one barrier interim record (`queued = 5`).
    for id in 10..=13 {
        sink.push(record(id, 1, true), true);
    }
    sink.push(record(14, 1, false), false);

    let (_, first) = capture_logs(|| assert!(sink.refuse()));
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(first[0].0, tracing::Level::WARN);
    assert_eq!(
        first[0].1,
        "connection records: 1 connection(s) refused (1 total): 4 closed records wait (5 queued, cap 4), stalled 0.0s"
    );

    // Cross well past 262,144 refusals before `WARN_EVERY`: quiet inside the window.
    elapsed_ms.store(5_000, AtomicOrdering::Relaxed);
    let (_, mid_window) = capture_logs(|| {
        for _ in 0..300_000 {
            assert!(sink.refuse());
        }
    });
    assert!(mid_window.is_empty(), "{mid_window:?}");
    assert_eq!(reader.refused(), 300_001);

    // At `WARN_EVERY` (10s), one summary warning reports the whole window.
    elapsed_ms.store(WARN_EVERY.as_millis() as u64, AtomicOrdering::Relaxed);
    let (_, first_window) = capture_logs(|| assert!(sink.refuse()));
    assert_eq!(first_window.len(), 1, "{first_window:?}");
    assert_eq!(first_window[0].0, tracing::Level::WARN);
    assert_eq!(
        first_window[0].1,
        "connection records: 300001 connection(s) refused (300002 total): 4 closed records wait (5 queued, cap 4), stalled 10.0s"
    );

    // Between 262,144 and 524,288 total refusals (no power of two crossed),
    // the next 10s window still warns on schedule.
    elapsed_ms.store(19_999, AtomicOrdering::Relaxed);
    let (_, before_second_window) = capture_logs(|| {
        for _ in 0..50_000 {
            assert!(sink.refuse());
        }
    });
    assert!(before_second_window.is_empty(), "{before_second_window:?}");

    elapsed_ms.store(20_000, AtomicOrdering::Relaxed);
    let (_, second_window) = capture_logs(|| assert!(sink.refuse()));
    assert_eq!(second_window.len(), 1, "{second_window:?}");
    assert_eq!(second_window[0].0, tracing::Level::WARN);
    assert_eq!(
        second_window[0].1,
        "connection records: 50001 connection(s) refused (350003 total): 4 closed records wait (5 queued, cap 4), stalled 20.0s"
    );
}

#[test]
fn recovery_logs_once_past_hysteresis_and_reentry_warns_at_once() {
    use portable_atomic::{AtomicU64, Ordering as AtomicOrdering};

    let base = Instant::now();
    let elapsed_ms = Arc::new(AtomicU64::new(0));
    let sink = {
        let elapsed_ms = elapsed_ms.clone();
        LosslessRecords::with_clock(4, move || {
            base + Duration::from_millis(elapsed_ms.load(AtomicOrdering::Relaxed))
        })
    };
    let mut reader = sink.reader().unwrap();

    for id in 1..=4 {
        sink.push(record(id, 1, true), true);
    }
    let (_, initial) = capture_logs(|| {
        assert!(sink.refuse());
        assert!(sink.refuse());
    });
    assert_eq!(initial.len(), 1, "{initial:?}");
    assert_eq!(initial[0].0, tracing::Level::WARN);

    // Trickling around `cap - 1 <-> cap` (3 <-> 4) admits one connection at 3
    // without falsely clearing the stall or spamming warn/recovery lines.
    let (_, flap_logs) = capture_logs(|| {
        for step in 1..=100u64 {
            elapsed_ms.store(step * 50, AtomicOrdering::Relaxed);
            assert!(reader.try_next().is_some());
            assert_eq!(reader.closed(), 3);
            assert!(!sink.refuse());
            sink.push(record(100 + step, 1, true), true);
            assert_eq!(reader.closed(), 4);
            assert!(sink.refuse());
        }
    });
    assert!(
        flap_logs.is_empty(),
        "boundary jitter must not spam logs: {flap_logs:?}"
    );

    // At 10s the ongoing stall still reports its continuous duration and count.
    elapsed_ms.store(10_000, AtomicOrdering::Relaxed);
    let (_, summary) = capture_logs(|| assert!(sink.refuse()));
    assert_eq!(summary.len(), 1, "{summary:?}");
    assert_eq!(
        summary[0].1,
        "connection records: 102 connection(s) refused (103 total): 4 closed records wait (4 queued, cap 4), stalled 10.0s"
    );

    // Draining to `recover_closed` (2 for `cap = 4`) emits one recovery log;
    // draining the rest emits no duplicate.
    elapsed_ms.store(12_500, AtomicOrdering::Relaxed);
    let (_, one_pop) = capture_logs(|| {
        assert!(reader.try_next().is_some());
    });
    assert!(
        one_pop.is_empty(),
        "3 closed records is still above hysteresis"
    );

    let (_, recovered) = capture_logs(|| {
        assert!(reader.try_next().is_some());
        assert_eq!(reader.closed(), 2);
        assert!(reader.try_next().is_some());
        assert!(reader.try_next().is_some());
        assert_eq!(reader.closed(), 0);
    });
    assert_eq!(recovered.len(), 1, "{recovered:?}");
    assert_eq!(recovered[0].0, tracing::Level::INFO);
    assert_eq!(
        recovered[0].1,
        "connection records: backlog cleared after 12.5s: 103 refused in stall (103 total), 2 queued (2 closed, cap 4)"
    );

    // A new saturation episode warns immediately, even within 10s of the last warn.
    elapsed_ms.store(13_000, AtomicOrdering::Relaxed);
    for id in 500..=503 {
        sink.push(record(id, 1, true), true);
    }
    let (_, reentered) = capture_logs(|| assert!(sink.refuse()));
    assert_eq!(reentered.len(), 1, "{reentered:?}");
    assert_eq!(reentered[0].0, tracing::Level::WARN);
    assert_eq!(
        reentered[0].1,
        "connection records: 1 connection(s) refused (104 total): 4 closed records wait (4 queued, cap 4), stalled 0.0s"
    );
}

#[test]
fn info_and_reader_report_capacity_closed_and_reader_state() {
    let sink = LosslessRecords::new(0);
    assert_eq!(
        sink.info(),
        ConnectionRecordsInfo {
            capacity: 1,
            queued: 0,
            closed: 0,
            dropped: 0,
            refused: 0,
            has_reader: false,
        }
    );

    let sink = LosslessRecords::new(2);
    let mut reader = sink.reader().unwrap();
    assert_eq!(reader.capacity(), 2);
    assert_eq!(reader.closed(), 0);
    assert!(sink.info().has_reader);

    sink.push(record(1, 1, false), true);
    sink.push(record(2, 2, true), true);
    // Queue length is at `cap = 2`: droppable interim drops, closed still queues.
    sink.push(record(3, 3, false), true);
    sink.push(record(4, 4, true), true);
    assert!(sink.refuse());

    assert_eq!(reader.queued(), 3);
    assert_eq!(reader.closed(), 2);
    assert_eq!(reader.dropped(), 1);
    assert_eq!(reader.refused(), 1);
    assert_eq!(
        sink.info(),
        ConnectionRecordsInfo {
            capacity: 2,
            queued: 3,
            closed: 2,
            dropped: 1,
            refused: 1,
            has_reader: true,
        }
    );

    assert_eq!(drain(&mut reader), [1, 2, 4]);
    drop(reader);
    assert_eq!(
        sink.info(),
        ConnectionRecordsInfo {
            capacity: 2,
            queued: 0,
            closed: 0,
            dropped: 1,
            refused: 1,
            has_reader: false,
        }
    );
}
