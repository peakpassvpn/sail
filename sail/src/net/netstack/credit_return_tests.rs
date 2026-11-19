//! A write held by packet budget: without a bound observer it waits for the
//! 10 ms retry; with one, a credit return wakes it before that retry is due.
//! Source prepared only; no compilation or execution granted by this file.
use super::super::channel::ChannelPacketIo;
use super::super::testing::tcp_packet_with_window;
use super::*;
use sail_netstack::{
    emit_tcp_segment_with_options, parse_ip_packet, parse_tcp_segment, BudgetProfile, SendControl,
    SeqNumber, TcpFlags,
};
use tokio::io::AsyncWriteExt;

const MSS: usize = 1_460;
const DOWNLOAD_BYTES: usize = 64 * 1_024;
const WARM_BYTES: usize = 256 * 1_024;

struct AbortOwner(tokio::task::JoinHandle<Result<(), RunnerError>>);
impl Drop for AbortOwner {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn sample(commands: &mut mpsc::Sender<TcpCommand>) -> StackStats {
    let (response, receiver) = oneshot::channel();
    commands
        .send(TcpCommand::StatsSnapshot { response })
        .await
        .unwrap();
    receiver.await.unwrap()
}

async fn settle() {
    // A runnable test task prevents paused Tokio time from auto-advancing.
    for _ in 0..512 {
        tokio::task::yield_now().await;
    }
}

async fn scenario(require_immediate_wake: bool) {
    let (input, input_rx) = tokio_mpsc::channel(64);
    let (output, mut output_rx) = tokio_mpsc::channel(64);
    let io = ChannelPacketIo::new(input_rx, output, 1);
    let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
    // A phone's TUN MTU, 9000, while the client's SYN below holds
    // segments to an MSS of 1460: not a jumbo-segment test.
    let mut config = RunnerConfig {
        mtu: 9_000,
        packets_per_step: 16,
        ..RunnerConfig::default()
    };
    config.tcp.max_segment_payload_bytes = 9_000;
    config.tcp.receive_credit_bytes = 4 * 1_024;
    config.tcp.max_receive_credit_bytes = Some(128 * 1_024);
    config.tcp.max_send_buffer_bytes = Some(256 * 1_024);
    let (accepted_tx, mut accepts) = tokio_mpsc::channel(4);
    let (udp_tx, _datagrams) = tokio_mpsc::channel(4);
    let (mut runtime, _) =
        NativeRuntime::new_with_sinks(io, ledger.clone(), config, 256, accepted_tx, udp_tx)
            .unwrap();
    if require_immediate_wake {
        let bound = credit_wake::bind(&ledger, &[Arc::clone(&runtime.credit.slot)]);
        assert!(bound);
        runtime.credit.set_bound(bound);
    }
    let mut commands = runtime.commands_tx.clone();
    let mut owner = AbortOwner(tokio::spawn(runtime.run()));
    let app: SocketAddr = "192.0.2.2:40000".parse().unwrap();
    let local: SocketAddr = "192.0.2.1:443".parse().unwrap();
    // Real checksum-valid App SYN with MSS1460 and WS6. Without scaling,
    // a 65535-byte peer window could not grant a full 64KiB commit.
    let syn = emit_tcp_segment_with_options(
        app,
        local,
        SendControl {
            sequence: SeqNumber::new(100),
            acknowledgment: SeqNumber::new(0),
            flags: TcpFlags::SYN,
            window: 65_535,
        },
        &[2, 4, 0x05, 0xb4, 3, 3, 6, 1],
        &[],
        64,
        1,
    )
    .unwrap();
    input.send(syn).await.unwrap();
    let wire = output_rx.recv().await.unwrap();
    let syn_ack = parse_tcp_segment(parse_ip_packet(&wire, true).unwrap(), true).unwrap();
    let first_data_sequence = syn_ack.meta.sequence.wrapping_add(1).get();
    input
        .send(tcp_packet_with_window(
            app,
            local,
            101,
            first_data_sequence,
            TcpFlags::ACK,
            65_535,
            &[],
        ))
        .await
        .unwrap();
    let mut accepted = accepts.recv().await.unwrap();

    // Warm only this real connection's cwnd, using small emitted packets
    // and actual ACK ingestion. Never mutate the TCB or substitute jumbo.
    let warm = vec![0x31; WARM_BYTES];
    let writer = async {
        accepted.stream.write_all(&warm).await.unwrap();
        accepted.stream.flush().await.unwrap();
    };
    let ack_reader = async {
        let mut received = 0;
        while received < WARM_BYTES {
            let wire = output_rx.recv().await.unwrap();
            assert!(wire.len() <= 1_500);
            let tcp = parse_tcp_segment(parse_ip_packet(&wire, true).unwrap(), true).unwrap();
            if tcp.payload.is_empty() {
                continue;
            }
            assert!(tcp.payload.len() <= MSS);
            assert!(tcp.payload.iter().all(|byte| *byte == 0x31));
            received += tcp.payload.len();
            let ack = tcp.meta.sequence.wrapping_add(tcp.payload.len()).get();
            input
                .send(tcp_packet_with_window(
                    app,
                    local,
                    101,
                    ack,
                    TcpFlags::ACK,
                    65_535,
                    &[],
                ))
                .await
                .unwrap();
        }
        assert_eq!(received, WARM_BYTES);
    };
    tokio::join!(writer, ack_reader);
    // Barrier: no late warm-up ACK or old packet lease can rescue the
    // pending write after this test starts holding all packet credit.
    for _ in 0..512 {
        let stats = sample(&mut commands).await;
        if stats.tcp_send_buffered_bytes == 0
            && stats.resources.used(ResourceKind::PacketBytes) == 0
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    let before = sample(&mut commands).await;
    assert_eq!(before.tcp_created_flows, 1);
    assert_eq!(before.tcp_send_buffered_bytes, 0);
    assert_eq!(before.resources.used(ResourceKind::PacketBytes), 0);
    assert!(output_rx.try_recv().is_err());

    // Actual ResourceLedger lease, not a mock semaphore/counter. This
    // represents another packet owner's allocation, released without ACK.
    let held = ledger
        .try_acquire(ResourceKind::PacketBytes, ledger.budget().packet_bytes)
        .unwrap();
    let denied_before = ledger.snapshot().denied;
    let download = vec![0x5a; DOWNLOAD_BYTES];
    let clock = tokio::time::Instant::now();
    assert_eq!(
        accepted.stream.write(&download).await.unwrap(),
        DOWNLOAD_BYTES,
        "must really grant/commit64KiB after warming cwnd"
    );
    settle().await;
    assert!(ledger.snapshot().denied > denied_before);
    assert_eq!(tokio::time::Instant::now(), clock);
    let blocked = sample(&mut commands).await;
    assert_eq!(blocked.tcp_created_flows, 1);
    assert_eq!(blocked.tcp_send_buffered_bytes, 0);
    assert!(output_rx.try_recv().is_err());
    let mut flush = Box::pin(accepted.stream.flush());
    assert!(futures::poll!(flush.as_mut()).is_pending());

    // No TCP input/ACK/window update from here onward. Only the shared
    // ledger lease drops; cwnd and peer window were already sufficient.
    drop(held);
    settle().await;
    assert_eq!(tokio::time::Instant::now(), clock);
    if require_immediate_wake {
        match futures::poll!(flush.as_mut()) {
            std::task::Poll::Ready(result) => result.unwrap(),
            std::task::Poll::Pending => {
                panic!("returned credit failed to wake native download before timer")
            }
        }
    } else {
        assert!(futures::poll!(flush.as_mut()).is_pending());
        assert!(output_rx.try_recv().is_err());
        tokio::time::advance(Duration::from_millis(9)).await;
        settle().await;
        assert!(futures::poll!(flush.as_mut()).is_pending());
        assert!(output_rx.try_recv().is_err());
        tokio::time::advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(
            tokio::time::Instant::now() - clock,
            Duration::from_millis(10)
        );
        match futures::poll!(flush.as_mut()) {
            std::task::Poll::Ready(result) => result.unwrap(),
            std::task::Poll::Pending => {
                panic!("existing timer failed to retry returned credit at10ms")
            }
        }
    }
    drop(flush);
    let mut received = Vec::new();
    while received.len() < DOWNLOAD_BYTES {
        let wire = output_rx
            .try_recv()
            .expect("64KiB should already be queued without another ACK");
        assert!(wire.len() <= 1_500);
        let tcp = parse_tcp_segment(parse_ip_packet(&wire, true).unwrap(), true).unwrap();
        assert!(!tcp.payload.is_empty() && tcp.payload.len() <= MSS);
        assert_eq!(
            tcp.meta.sequence.get(),
            first_data_sequence
                .wrapping_add(WARM_BYTES as u32)
                .wrapping_add(received.len() as u32)
        );
        received.extend_from_slice(tcp.payload);
    }
    assert_eq!(received, download);
    assert_eq!(sample(&mut commands).await.tcp_created_flows, 1);
    assert!(
        accepts.try_recv().is_err(),
        "must retain the same connection"
    );
    drop(accepted);
    owner.0.abort();
    let _ = (&mut owner.0).await;
    assert_eq!(ledger.snapshot().used(ResourceKind::TcpFlows), 0);
}

#[tokio::test(start_paused = true)]
async fn same_source_unbound_control_waits_for_existing_10ms_retry() {
    scenario(false).await;
}

#[tokio::test(start_paused = true)]
async fn required_small_mss_credit_return_wakes_before_existing_retry_deadline() {
    // Bound: the write goes before the 10 ms retry is due.
    scenario(true).await;
}
