use super::*;
use crate::adapter::{OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
use crate::session::SocksAddr;
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

struct MockStream {
    data: Vec<u8>,
    read_pos: usize,
}

impl AsyncRead for MockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let rem = self.data.len() - self.read_pos;
        if rem == 0 {
            return Poll::Ready(Ok(()));
        }
        let to_read = std::cmp::min(rem, buf.remaining());
        buf.put_slice(&self.data[self.read_pos..self.read_pos + to_read]);
        self.read_pos += to_read;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn mock(data: &[u8]) -> AnyStream {
    Box::new(MockStream {
        data: data.to_vec(),
        read_pos: 0,
    })
}

struct MockRecv(usize);

#[async_trait]
impl OutboundDatagramRecvHalf for MockRecv {
    async fn recv_from(&mut self, _buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        match std::mem::take(&mut self.0) {
            0 => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
            n => Ok((n, SocksAddr::any())),
        }
    }
}

struct MockSend;

#[async_trait]
impl OutboundDatagramSendHalf for MockSend {
    async fn send_to(&mut self, buf: &[u8], _dst_addr: &SocksAddr) -> io::Result<usize> {
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A datagram whose receiving half gets one datagram of `.0` bytes.
struct MockDatagram(usize);

impl OutboundDatagram for MockDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(MockRecv(self.0)), Box::new(MockSend))
    }
}

fn session(inbound: &str, outbound: &str, user: Option<&UserRef>, network: Network) -> Session {
    Session {
        inbound_tag: inbound.into(),
        outbound_tag: outbound.into(),
        user: user.cloned(),
        network,
        destination: SocksAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8001)),
        ..Default::default()
    }
}

fn counts(up: u64, down: u64, tcp: u64, udp: u64) -> Counts {
    Counts { up, down, tcp, udp }
}

fn find<'a>(counts: &'a [(String, Counts)], name: &str) -> Option<&'a Counts> {
    counts.iter().find(|(n, _)| n == name).map(|(_, c)| c)
}

#[tokio::test]
async fn test_stat_stream_non_empty_buf() {
    let sm = StatManager::default();
    let mut stream = sm.stat_stream(mock(&[1, 2, 3, 4, 5]), Session::default());

    let mut data = vec![0u8; 20];
    // Simulate existing data in buffer
    let mut buf = ReadBuf::new(&mut data);
    buf.put_slice(&[0xAA; 5]);
    futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut buf))
        .await
        .unwrap();

    assert_eq!(buf.filled().len(), 10);
    assert_eq!(sm.connections()[0].bytes_recvd(), 5);
}

/// A connection the API closes fails its reads and writes, waiting
/// ones too.
#[tokio::test]
async fn a_closed_connection_fails_its_reads_and_writes() {
    let sm = StatManager::default();
    let (a, _b) = tokio::io::duplex(64);
    let mut stream = sm.stat_stream(Box::new(a), Session::default());
    let id = sm.connections()[0].id;
    let reading = tokio::spawn(async move {
        let mut buf = [0u8; 8];
        let read = stream.read(&mut buf).await;
        (read, stream.write_all(b"x").await)
    });
    tokio::task::yield_now().await;
    assert!(sm.close(id));
    let (read, write) = reading.await.unwrap();
    assert_eq!(read.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(write.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    assert!(!sm.close(id + 1));
}

#[test]
fn a_datagram_session_ends_when_both_halves_are_dropped() {
    let sm = StatManager::default();
    let dgram = sm.stat_outbound_datagram(
        Box::new(MockDatagram(0)),
        session("in", "out", None, Network::Udp),
    );
    assert_eq!(sm.live(), 1);
    let (recv_half, send_half) = dgram.split();
    assert_eq!(sm.live(), 1);
    drop(recv_half);
    assert_eq!(sm.live(), 1);
    drop(send_half);
    assert_eq!(sm.live(), 0);

    // One never split ends when it is dropped.
    drop(sm.stat_outbound_datagram(
        Box::new(MockDatagram(0)),
        session("in", "out", None, Network::Udp),
    ));
    assert_eq!(sm.live(), 0);
}

/// A connection leaves the live ones as it is dropped, with no task to
/// clean up after it.
#[tokio::test]
async fn a_stream_is_retired_when_dropped() {
    let sm = StatManager::new(10, UserRegistry::default());
    let stream = sm.stat_stream(mock(b""), Session::default());
    assert_eq!(sm.live(), 1);
    drop(stream);
    assert_eq!(sm.live(), 0);
    assert_eq!(sm.recent().len(), 1);
}

/// The outbound's side counts what it writes as up and what it reads as
/// down; the client's side the other way round; a datagram what it sends
/// as up. Each connection counts to its user, inbound and outbound.
#[tokio::test]
async fn bytes_count_to_the_user_inbound_and_outbound_each_way() {
    let users = UserRegistry::default();
    let alice = users.bind("alice");
    let sm = StatManager::new(0, users.clone());

    let mut out = sm.stat_stream(
        mock(b"12345"),
        session("in", "out", Some(&alice), Network::Tcp),
    );
    out.write_all(b"abc").await.unwrap();
    let mut buf = Vec::new();
    out.read_to_end(&mut buf).await.unwrap();

    let mut client = sm.stat_inbound_stream(
        mock(b"1234567"),
        session("in", "direct", None, Network::Tcp),
    );
    client.write_all(b"ab").await.unwrap();
    client.read_to_end(&mut buf).await.unwrap();

    let dgram = sm.stat_outbound_datagram(
        Box::new(MockDatagram(11)),
        session("in2", "out", Some(&alice), Network::Udp),
    );
    let (mut recv, mut send) = dgram.split();
    send.send_to(b"xyzw", &SocksAddr::any()).await.unwrap();
    let mut dbuf = [0u8; 64];
    recv.recv_from(&mut dbuf).await.unwrap();

    assert_eq!(alice.traffic().counts(), counts(3 + 4, 5 + 11, 1, 1));
    let report = sm.traffic();
    assert_eq!(find(&report.users, "alice"), Some(&counts(7, 16, 1, 1)));
    assert_eq!(
        find(&report.inbounds, "in"),
        Some(&counts(3 + 7, 5 + 2, 2, 0))
    );
    assert_eq!(find(&report.inbounds, "in2"), Some(&counts(4, 11, 0, 1)));
    assert_eq!(find(&report.outbounds, "out"), Some(&counts(7, 16, 1, 1)));
    assert_eq!(find(&report.outbounds, "direct"), Some(&counts(7, 2, 1, 0)));
    assert_eq!(sm.totals(), (3 + 7 + 4, 5 + 2 + 11));

    // They stay once the connections are gone.
    drop((out, client, recv, send));
    assert_eq!(sm.live(), 0);
    assert_eq!(sm.totals(), (14, 18));
    assert_eq!(alice.traffic().counts().up, 7);
}

/// The counts a cache file kept go on, users' too, but the totals count
/// from the start.
#[tokio::test]
async fn kept_counts_go_on_but_not_in_the_totals() {
    let users = UserRegistry::default();
    let sm = StatManager::new(0, users.clone());
    sm.restore(TrafficReport {
        users: vec![("alice".into(), counts(100, 200, 3, 4))],
        inbounds: vec![
            ("in".into(), counts(1000, 2000, 5, 6)),
            ("gone".into(), counts(7, 7, 7, 7)),
        ],
        outbounds: vec![("out".into(), counts(10, 20, 1, 1))],
    });
    let alice = users.bind("alice");
    let mut s = sm.stat_stream(mock(b""), session("in", "out", Some(&alice), Network::Tcp));
    s.write_all(b"abc").await.unwrap();
    assert_eq!(alice.traffic().counts(), counts(103, 200, 4, 4));
    let report = sm.traffic();
    assert_eq!(
        find(&report.inbounds, "in"),
        Some(&counts(1003, 2000, 6, 6))
    );
    assert_eq!(find(&report.outbounds, "out"), Some(&counts(13, 20, 2, 1)));
    assert_eq!(sm.totals(), (3, 0));
    // A user not kept starts from nothing.
    assert_eq!(users.bind("bob").traffic().counts(), Counts::default());
}

/// The counts of a tag no longer configured go once nothing counts to it,
/// and stay in the totals.
#[tokio::test]
async fn unconfigured_tags_are_pruned_once_idle() {
    let sm = StatManager::default();
    let mut s = sm.stat_stream(mock(b""), session("old", "gone", None, Network::Tcp));
    s.write_all(b"abcd").await.unwrap();
    let only = |tags: &[&str]| tags.iter().map(|t| t.to_string()).collect::<HashSet<_>>();

    sm.configure(&only(&["new"]), &only(&["kept"]));
    assert!(
        find(&sm.traffic().outbounds, "gone").is_some(),
        "still counted to"
    );
    drop(s);
    sm.configure(&only(&["new"]), &only(&["kept"]));
    let report = sm.traffic();
    assert!(find(&report.outbounds, "gone").is_none());
    assert!(find(&report.inbounds, "old").is_none());
    assert_eq!(sm.totals(), (4, 0));
}

/// Only TCP connections not finished both ways are still to drain.
#[tokio::test]
async fn open_streams_counts_tcp_not_finished_both_ways() {
    let sm = StatManager::default();
    let mut done = sm.stat_stream(mock(b""), session("in", "out", None, Network::Tcp));
    let _open = sm.stat_stream(mock(b"x"), session("in", "out", None, Network::Tcp));
    let _udp = sm.stat_outbound_datagram(
        Box::new(MockDatagram(0)),
        session("in", "out", None, Network::Udp),
    );
    assert_eq!(sm.open_streams(), 2);
    let mut buf = [0u8; 4];
    assert_eq!(done.read(&mut buf).await.unwrap(), 0);
    done.shutdown().await.unwrap();
    assert_eq!(sm.open_streams(), 1);
    assert_eq!(sm.live(), 3);
}

#[tokio::test]
async fn recent_keeps_the_latest_finished() {
    let sm = StatManager::new(3, UserRegistry::default());
    for _ in 0..(SHARDS * 2 + 5) {
        drop(sm.stat_stream(mock(b""), Session::default()));
    }
    let recent = sm.recent();
    assert_eq!(recent.len(), 3);
    let last = (SHARDS * 2 + 5) as u64;
    assert_eq!(recent.last().unwrap().id, last);
    assert!(recent.windows(2).all(|w| w[0].id < w[1].id));
}

#[test]
fn striped_counts_sum_across_threads() {
    let traffic = Arc::new(Traffic::new(counts(5, 0, 0, 0)));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let traffic = traffic.clone();
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    traffic.up.add(2);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(traffic.counts().up, 5 + 8 * 1000 * 2);
    assert_eq!(traffic.since_start().0, 8 * 1000 * 2);
}
