use super::*;
use crate::control::events::{End, RecordKind};
use crate::session::{Network, SocksAddr};
use std::time::Duration;

fn record(id: u64, user: &str, up: u64, down: u64, closed: bool) -> Arc<ConnectionRecord> {
    let at = std::time::UNIX_EPOCH + Duration::from_secs(1000 + id);
    Arc::new(ConnectionRecord {
        id,
        run: std::time::UNIX_EPOCH,
        seq: 0,
        kind: match closed {
            true => RecordKind::Closed(End::Finished),
            false => RecordKind::Interim,
        },
        network: Network::Tcp,
        user: Some(user.into()),
        inbound: "in".into(),
        source: "127.0.0.1:1".parse().unwrap(),
        destination: SocksAddr::any(),
        request_destination: None,
        domain: None,
        domain_source: None,
        chain: vec!["g".into(), "out".into()],
        up,
        down,
        up_total: up,
        down_total: down,
        start: at,
        since: at,
        at,
    })
}

/// Under the cap, records come in order; past it they fold by user,
/// inbound and outbound, and the summaries come once the queue is empty:
/// every byte is read once.
#[test]
fn past_the_cap_records_fold_and_no_byte_is_lost() {
    let sink = LosslessRecords::new(2);
    let mut reader = sink.reader().unwrap();
    for (id, user, up) in [
        (1, "a", 1),
        (2, "a", 2),
        (3, "a", 4),
        (4, "a", 8),
        (5, "b", 16),
    ] {
        sink.push(record(id, user, up, up * 10, id != 4));
    }
    assert_eq!((reader.queued(), reader.folded_total()), (2, 3));
    let mut read = Vec::new();
    while let Some(r) = reader.try_next() {
        read.push(r);
    }
    assert!(matches!(&read[0], Record::Connection(r) if r.id == 1));
    assert!(matches!(&read[1], Record::Connection(r) if r.id == 2));
    let mut folded: Vec<_> = read[2..]
        .iter()
        .map(|r| match r {
            Record::Folded(s) => s.clone(),
            other => panic!("{:?}", other),
        })
        .collect();
    folded.sort_by(|x, y| x.user.cmp(&y.user));
    assert_eq!(folded.len(), 2);
    let a = &folded[0];
    assert_eq!(
        (
            a.user.as_deref(),
            a.outbound.as_str(),
            a.up,
            a.down,
            a.records,
            a.closed
        ),
        (Some("a"), "out", 12, 120, 2, 1)
    );
    assert!(a.since < a.at);
    assert_eq!((folded[1].up, folded[1].records), (16, 1));
    let up: u64 = read
        .iter()
        .map(|r| match r {
            Record::Connection(r) => r.up,
            Record::Folded(s) => s.up,
        })
        .sum();
    assert_eq!(up, 1 + 2 + 4 + 8 + 16);
    // Drained: what comes now is queued again.
    sink.push(record(6, "a", 32, 0, true));
    assert!(matches!(reader.try_next(), Some(Record::Connection(r)) if r.id == 6));
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
    sink.push(record(1, "a", 1, 1, true));
    let got = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(got, Record::Connection(r) if r.id == 1));
}
