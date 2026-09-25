use tracing::{debug, error};

use super::protocol::{
    Frame, DATA_HEADER_LEN, FIN_LEN, MTYP_DATA, MTYP_FIN, MTYP_PING, MTYP_PONG, MTYP_RST,
};
use bytes::{Buf, Bytes, BytesMut};
use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

struct SubConnection<S> {
    stream: S,
    read_buf: BytesMut,
    write_buf: BytesMut,
    closed: bool, // Mark if this sub-connection is dead
}

impl<S> SubConnection<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: BytesMut::with_capacity(4096),
            write_buf: BytesMut::with_capacity(4096),
            closed: false,
        }
    }
}

pub struct MptpStream<S> {
    subs: Vec<SubConnection<S>>,
    new_subs_rx: Option<mpsc::UnboundedReceiver<(S, Option<uuid::Uuid>)>>, // Allow passing CID
    read_buffer: BytesMut,
    next_pn: u64,

    // Reordering logic
    expected_read_pn: u64,
    reorder_buffer: BTreeMap<u64, Bytes>,

    /// The peer's last packet, once its FIN has come.
    fin_pn: Option<u64>,
    /// Whether this side's FIN is queued.
    fin_sent: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> MptpStream<S> {
    pub fn new(streams: Vec<S>) -> Self {
        let subs = streams.into_iter().map(|s| SubConnection::new(s)).collect();
        Self {
            subs,
            new_subs_rx: None,
            read_buffer: BytesMut::new(),
            next_pn: 1,
            expected_read_pn: 1,
            reorder_buffer: BTreeMap::new(),
            fin_pn: None,
            fin_sent: false,
        }
    }

    pub fn new_with_receiver(rx: mpsc::UnboundedReceiver<(S, Option<uuid::Uuid>)>) -> Self {
        Self {
            subs: Vec::new(),
            new_subs_rx: Some(rx),
            read_buffer: BytesMut::new(),
            next_pn: 1,
            expected_read_pn: 1,
            reorder_buffer: BTreeMap::new(),
            fin_pn: None,
            fin_sent: false,
        }
    }

    pub fn new_with_receiver_and_initial(
        streams: Vec<S>,
        rx: mpsc::UnboundedReceiver<(S, Option<uuid::Uuid>)>,
    ) -> Self {
        let subs = streams.into_iter().map(|s| SubConnection::new(s)).collect();
        Self {
            subs,
            new_subs_rx: Some(rx),
            read_buffer: BytesMut::new(),
            next_pn: 1,
            expected_read_pn: 1,
            reorder_buffer: BTreeMap::new(),
            fin_pn: None,
            fin_sent: false,
        }
    }

    /// Whether the peer's FIN has come, and every packet up to it.
    fn finished(&self) -> bool {
        self.fin_pn.is_some_and(|last| self.expected_read_pn > last)
    }

    fn poll_new_subs(&mut self, cx: &mut Context<'_>) {
        if let Some(rx) = &mut self.new_subs_rx {
            loop {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some((stream, _))) => {
                        self.subs.push(SubConnection::new(stream));
                    }
                    Poll::Ready(None) => {
                        // Channel closed, no more new subs
                        self.new_subs_rx = None;
                        break;
                    }
                    Poll::Pending => break,
                }
            }
        }

        // Periodically cleanup closed subs if the list gets too long
        if self.subs.len() > 16 {
            self.subs.retain(|s| !s.closed);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MptpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check for new sub-connections
        this.poll_new_subs(cx);

        // Serve buffered data first
        if !this.read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), this.read_buffer.len());
            buf.put_slice(&this.read_buffer.split_to(len));
            return Poll::Ready(Ok(()));
        }

        if this.finished() {
            return Poll::Ready(Ok(()));
        }

        let mut any_progress = false;
        let mut all_eof = !this.subs.is_empty(); // If no subs, not EOF (unless closed), but maybe pending
        if this.subs.is_empty() {
            all_eof = false; // Waiting for subs?
        }

        // Temporary buffer for reading from socket
        let mut temp_buf = [0u8; 4096];

        // First pass: Read from all active subs
        for (i, sub) in this.subs.iter_mut().enumerate() {
            if sub.closed {
                continue;
            }

            // Read from socket
            let mut read_buf = ReadBuf::new(&mut temp_buf);
            match Pin::new(&mut sub.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if !filled.is_empty() {
                        sub.read_buf.extend_from_slice(filled);
                        any_progress = true;
                        all_eof = false;
                    } else {
                        // EOF for this sub
                        debug!("sub {} EOF, marking closed", i);
                        sub.closed = true;
                        // Don't return EOF yet, others might be alive
                    }
                }
                Poll::Ready(Err(e)) => {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        debug!("sub {} UnexpectedEof, marking closed", i);
                    } else {
                        error!("sub {} read error: {}, marking closed", i, e);
                    }
                    sub.closed = true;
                    // Don't return error, just close this sub
                }
                Poll::Pending => {
                    all_eof = false;
                }
            }
        }

        // Cleanup closed subs?
        // Removing from Vec is tricky while iterating, but we can filter later or just ignore marked closed.
        // For simplicity, we just keep them but skip them.
        // Ideally we should remove them to free resources, but index stability matters for logging.
        // Let's just keep them marked closed.

        // Check if ALL are closed
        let all_closed = this.subs.iter().all(|s| s.closed);
        // Frames still buffered are processed below, whether or not their
        // path has closed since.
        let unread = this.subs.iter().any(|s| !s.read_buf.is_empty());
        if all_closed && !unread && !this.subs.is_empty() && this.new_subs_rx.is_none() {
            if this.finished() {
                return Poll::Ready(Ok(()));
            }
            debug!("all sub-connections closed before the data was complete");
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "all sub-connections closed before the data was complete",
            )));
        }

        // Second pass: Process frames from buffer
        for (i, sub) in this.subs.iter_mut().enumerate() {
            if sub.read_buf.is_empty() {
                continue;
            }

            // Process frames
            loop {
                if sub.read_buf.is_empty() {
                    break;
                }

                let mtyp = sub.read_buf[0];
                let needed = match mtyp {
                    MTYP_DATA => {
                        if sub.read_buf.len() < DATA_HEADER_LEN {
                            0
                        } else {
                            let mut slice = &sub.read_buf[1 + 8..]; // Skip MTYP+PN
                            let len = slice.get_u32() as usize;
                            DATA_HEADER_LEN + len
                        }
                    }
                    MTYP_FIN => FIN_LEN,
                    MTYP_RST | MTYP_PING | MTYP_PONG => 1,
                    _ => {
                        error!("unknown MTYP: {}", mtyp);
                        1 // Consume 1 byte to maybe recover? Or Error?
                    }
                };

                if needed == 0 || sub.read_buf.len() < needed {
                    break;
                }

                // Have full frame
                match mtyp {
                    MTYP_DATA => {
                        // Parse manually to avoid cloning payload if possible, but BytesMut split is cheap
                        let pn_slice = &sub.read_buf[1..9];
                        let mut pn_reader = pn_slice;
                        let pn = pn_reader.get_u64();

                        sub.read_buf.advance(DATA_HEADER_LEN);
                        let payload_len = needed - DATA_HEADER_LEN;
                        let payload = sub.read_buf.split_to(payload_len).freeze();

                        if pn < this.expected_read_pn {
                            // Duplicate or old packet, ignore
                        } else if pn == this.expected_read_pn {
                            // Expected packet
                            this.read_buffer.extend_from_slice(&payload);
                            this.expected_read_pn += 1;
                            any_progress = true;

                            // Check if we can drain reorder buffer
                            while let Some(payload) =
                                this.reorder_buffer.remove(&this.expected_read_pn)
                            {
                                // log::trace!("Draining reorder buffer PN: {}", this.expected_read_pn);
                                this.read_buffer.extend_from_slice(&payload);
                                this.expected_read_pn += 1;
                            }
                        } else {
                            // Future packet, buffer it
                            if !this.reorder_buffer.contains_key(&pn) {
                                // Limit reorder buffer size to 1024 packets or ~4MB
                                if this.reorder_buffer.len() < 1024 {
                                    this.reorder_buffer.insert(pn, payload);
                                }
                            }
                        }
                    }
                    MTYP_FIN => {
                        let last_pn = (&sub.read_buf[1..FIN_LEN]).get_u64();
                        debug!("received fin from sub {}, last packet {}", i, last_pn);
                        sub.read_buf.advance(FIN_LEN);
                        this.fin_pn = Some(last_pn);
                        // The FIN is the last frame on its path.
                        break;
                    }
                    MTYP_RST => {
                        debug!("received RST from sub {}", i);
                        sub.read_buf.advance(1);
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "peer sent RST",
                        )));
                    }
                    _ => {
                        sub.read_buf.advance(1);
                    }
                }
            }
        }

        if !this.read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), this.read_buffer.len());
            buf.put_slice(&this.read_buffer.split_to(len));
            return Poll::Ready(Ok(()));
        }

        if this.finished() {
            return Poll::Ready(Ok(()));
        }

        if all_eof && !this.subs.is_empty() {
            debug!("all sub-connections EOF before the data was complete");
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "all sub-connections ended before the data was complete",
            )));
        }

        if any_progress {
            cx.waker().wake_by_ref();
        }

        Poll::Pending
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MptpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Check for new sub-connections
        this.poll_new_subs(cx);

        // If no subs, we can't write yet? Or buffer internally?
        // For now, if no subs, return Pending until we get one.
        if this.subs.is_empty() {
            return Poll::Pending;
        }

        // Check backpressure (if ALL active buffers are too full)
        let mut all_full = true;
        let mut active_subs = 0;

        for sub in &this.subs {
            if !sub.closed {
                active_subs += 1;
                if sub.write_buf.len() <= 64 * 1024 {
                    all_full = false;
                }
            }
        }

        if active_subs == 0 && !this.subs.is_empty() {
            // All closed
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "all sub-connections failed (write)",
            )));
        }

        if all_full {
            // Try to flush - maybe it helps?
            let _ = Pin::new(&mut *this).poll_flush(cx);

            // Re-check if still full after flush attempt
            all_full = true;
            for sub in &this.subs {
                if sub.write_buf.len() <= 64 * 1024 {
                    all_full = false;
                    break;
                }
            }

            if all_full {
                // If flush returned Ready but buffer is still full (unlikely if logic is correct),
                // or if flush returned Pending, we must return Pending.
                // But if flush returned Ready, we MUST have drained the buffer.
                // If flush returned Pending, waker is registered.
                return Poll::Pending;
            }
            // If not full anymore, continue to write!
        }

        let pn = this.next_pn;
        this.next_pn += 1;

        let frame = Frame::Data {
            pn,
            payload: Bytes::copy_from_slice(buf),
        };

        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded);
        let encoded_bytes = encoded.freeze();

        // Broadcast to all non-full subs
        let mut sent_count = 0;
        for sub in &mut this.subs {
            if !sub.closed {
                if sub.write_buf.len() <= 64 * 1024 {
                    sub.write_buf.extend_from_slice(&encoded_bytes);
                    sent_count += 1;
                }
            }
        }

        if sent_count == 0 {
            // Should not happen due to all_full check above, but for safety:
            return Poll::Pending;
        }

        // Try flush immediately
        let _ = Pin::new(&mut *this).poll_flush(cx);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check for new sub-connections
        this.poll_new_subs(cx);

        let mut all_flushed = true;
        let mut any_flushed = false;
        let mut active_subs = 0;

        for (i, sub) in this.subs.iter_mut().enumerate() {
            if sub.closed {
                continue;
            }
            active_subs += 1;
            while !sub.write_buf.is_empty() {
                match Pin::new(&mut sub.stream).poll_write(cx, &sub.write_buf) {
                    Poll::Ready(Ok(n)) => {
                        sub.write_buf.advance(n);
                    }
                    Poll::Ready(Err(e)) => {
                        error!("sub {} write error: {}, marking closed", i, e);
                        sub.closed = true;
                        // Don't return error yet
                        break;
                    }
                    Poll::Pending => {
                        all_flushed = false;
                        break;
                    }
                }
            }
            if !sub.closed && sub.write_buf.is_empty() {
                any_flushed = true;
            }
        }

        if all_flushed || (any_flushed && active_subs > 0) {
            // If at least one path is flushed, we consider the overall stream "flushed" enough
            // to continue, but we'll keep trying to flush others in future calls.
            Poll::Ready(Ok(()))
        } else if active_subs == 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Check for new sub-connections
        this.poll_new_subs(cx);

        // The FIN goes down every path once, naming the last packet so the
        // peer can wait for packets still on other paths.
        if !this.fin_sent {
            let mut encoded = BytesMut::new();
            Frame::Fin {
                last_pn: this.next_pn - 1,
            }
            .encode(&mut encoded);
            for sub in this.subs.iter_mut().filter(|s| !s.closed) {
                sub.write_buf.extend_from_slice(&encoded);
            }
            this.fin_sent = true;
        }

        // A packet may have gone down one path only, when the others were
        // full: every path is written out before any is shut down, or the
        // packets on it would be lost.
        let mut pending = false;
        let mut active_subs = 0;
        for (i, sub) in this.subs.iter_mut().enumerate() {
            if sub.closed {
                continue;
            }
            active_subs += 1;
            while !sub.write_buf.is_empty() {
                match Pin::new(&mut sub.stream).poll_write(cx, &sub.write_buf) {
                    Poll::Ready(Ok(0)) => {
                        sub.closed = true;
                        break;
                    }
                    Poll::Ready(Ok(n)) => sub.write_buf.advance(n),
                    Poll::Ready(Err(e)) => {
                        debug!("sub {} write error while closing: {}", i, e);
                        sub.closed = true;
                        break;
                    }
                    Poll::Pending => {
                        pending = true;
                        break;
                    }
                }
            }
        }
        if pending {
            return Poll::Pending;
        }

        for sub in this.subs.iter_mut().filter(|s| !s.closed) {
            match Pin::new(&mut sub.stream).poll_shutdown(cx) {
                Poll::Ready(_) => {}
                Poll::Pending => pending = true,
            }
        }
        if pending {
            return Poll::Pending;
        }
        if active_subs > 0 && this.subs.iter().all(|s| s.closed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "all sub-connections failed while closing",
            )));
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_single_stream_write_read() {
        use super::super::protocol::MTYP_DATA;
        let (client, mut server) = tokio::io::duplex(1024);
        let mut mptp = MptpStream::new(vec![client]);

        // Write to mptp
        mptp.write_all(b"hello").await.unwrap();

        // Read from server (raw frame)
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        // Expect: MTYP(1) + PN(8) + LEN(4) + PAYLOAD(5)
        assert_eq!(n, 1 + 8 + 4 + 5);
        assert_eq!(buf[0], MTYP_DATA);
        // PN should be 1
        assert_eq!(&buf[1..9], &1u64.to_be_bytes());
        // LEN should be 5
        assert_eq!(&buf[9..13], &5u32.to_be_bytes());
        // Payload
        assert_eq!(&buf[13..18], b"hello");
    }

    #[tokio::test]
    async fn test_deduplication() {
        let (c1, mut s1) = tokio::io::duplex(1024);
        let (c2, mut s2) = tokio::io::duplex(1024);
        let mut mptp = MptpStream::new(vec![c1, c2]);

        // Construct a frame
        let frame = Frame::Data {
            pn: 1,
            payload: Bytes::from_static(b"data"),
        };
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded);
        let bytes = encoded.freeze();

        // Send to both underlying streams
        s1.write_all(&bytes).await.unwrap();
        s2.write_all(&bytes).await.unwrap();

        // Read from mptp
        let mut buf = [0u8; 10];
        let n = mptp.read(&mut buf).await.unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"data");

        // Try read again - should be empty/pending (no new data)
        // Write another packet with DIFFERENT PN to s1
        let frame2 = Frame::Data {
            pn: 2,
            payload: Bytes::from_static(b"more"),
        };
        let mut encoded2 = BytesMut::new();
        frame2.encode(&mut encoded2);
        s1.write_all(&encoded2).await.unwrap();

        let n = mptp.read(&mut buf).await.unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"more");
    }

    #[tokio::test]
    async fn test_dynamic_add() {
        let (c1, mut s1) = tokio::io::duplex(1024);
        let (tx, rx) = mpsc::unbounded_channel();
        let mut mptp = MptpStream::new_with_receiver(rx);
        tx.send((c1, None)).unwrap();

        // Write to mptp (should go to s1)
        mptp.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 1024];
        let n = s1.read(&mut buf).await.unwrap();
        assert!(n > 0);
    }

    #[tokio::test]
    async fn test_resilience_to_stuck_sub() {
        let (c1, mut s1) = tokio::io::duplex(1024);
        let (c2, _s2) = tokio::io::duplex(1024); // s2 is never read, so c2 will become full
        let mut mptp = MptpStream::new(vec![c1, c2]);

        // Read from s1 in a background task to keep c1 empty
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok(n) = s1.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });

        // Write enough that c2 is definitely full but mptp shouldn't hang
        for i in 0..100 {
            let msg = format!("hello {}", i);
            mptp.write_all(msg.as_bytes()).await.unwrap();
        }

        // Flush should succeed because c1 is flushed
        mptp.flush().await.unwrap();
    }

    fn data_frame(pn: u64, payload: &'static [u8]) -> BytesMut {
        let mut encoded = BytesMut::new();
        Frame::Data {
            pn,
            payload: Bytes::from_static(payload),
        }
        .encode(&mut encoded);
        encoded
    }

    /// A packet that went down one path only is still read when the FIN
    /// comes first down another.
    #[tokio::test]
    async fn fin_on_one_path_waits_for_data_still_on_another() {
        let (c1, mut s1) = tokio::io::duplex(1024);
        let (c2, mut s2) = tokio::io::duplex(1024);
        let mut mptp = MptpStream::new(vec![c1, c2]);

        let mut fin = BytesMut::new();
        Frame::Fin { last_pn: 2 }.encode(&mut fin);
        // Path 1 carries packet 1 and the FIN; packet 2 is late on path 2.
        s1.write_all(&data_frame(1, b"first")).await.unwrap();
        s1.write_all(&fin).await.unwrap();
        let late = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            s2.write_all(&data_frame(2, b"second")).await.unwrap();
            s2
        });

        let mut received = Vec::new();
        mptp.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"firstsecond");
        drop(late.await.unwrap());
        drop(s1);
    }

    /// Paths closing with packets missing is an error, not a short read.
    #[tokio::test]
    async fn paths_ending_before_the_last_packet_is_an_error() {
        let (c1, mut s1) = tokio::io::duplex(1024);
        let mut mptp = MptpStream::new(vec![c1]);
        let mut fin = BytesMut::new();
        Frame::Fin { last_pn: 2 }.encode(&mut fin);
        s1.write_all(&data_frame(1, b"first")).await.unwrap();
        s1.write_all(&fin).await.unwrap();
        drop(s1);

        let mut received = Vec::new();
        let err = mptp.read_to_end(&mut received).await.unwrap_err();
        assert_eq!(received, b"first");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }

    /// Everything written before a shutdown arrives, over paths too small
    /// to take it at once.
    #[tokio::test]
    async fn shutdown_delivers_everything_written() {
        let (c1, s1) = tokio::io::duplex(256);
        let (c2, s2) = tokio::io::duplex(256);
        let mut writer = MptpStream::new(vec![c1, c2]);
        let mut reader = MptpStream::new(vec![s1, s2]);

        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();
        let send = tokio::spawn(async move {
            for chunk in data.chunks(3000) {
                writer.write_all(chunk).await.unwrap();
            }
            writer.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        send.await.unwrap();
        assert_eq!(received.len(), expected.len());
        assert!(received == expected);
    }
}
