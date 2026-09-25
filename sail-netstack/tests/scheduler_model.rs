use std::time::Duration;

use sail_netstack::{EnqueueError, FlowId, Scheduler, SchedulerConfig, WorkClass};

fn config() -> SchedulerConfig {
    SchedulerConfig {
        quantum_bytes: 1_000,
        max_packets_per_round: 32,
        max_bytes_per_round: 4_000,
        max_time_per_round: Duration::from_secs(1),
        max_contiguous_flow_bytes: 1_000,
        max_queued_packets: 64,
        max_queued_bytes: 8_000,
        max_active_flows: 4,
        max_packets_per_flow: 16,
        max_control_packets: 2,
        max_packet_bytes: 1_000,
    }
}

#[test]
fn control_service_cannot_be_disabled() {
    let mut limits = config();
    limits.max_control_packets = 0;
    assert!(Scheduler::<()>::new(limits).is_err());
}

#[test]
fn byte_drr_balances_large_and_small_packets() {
    let mut scheduler = Scheduler::new(config()).unwrap();
    let large = FlowId::new(1);
    let small = FlowId::new(2);
    scheduler
        .enqueue(
            WorkClass::Data {
                flow: large,
                weight: 1,
            },
            1_000,
            "large",
        )
        .unwrap();
    for _ in 0..10 {
        scheduler
            .enqueue(
                WorkClass::Data {
                    flow: small,
                    weight: 1,
                },
                100,
                "small",
            )
            .unwrap();
    }
    let mut large_bytes = 0;
    let mut small_bytes = 0;
    let stats = scheduler.run_round(|class, _| match class {
        WorkClass::Data { flow, .. } if flow == large => large_bytes += 1_000,
        WorkClass::Data { flow, .. } if flow == small => small_bytes += 100,
        _ => unreachable!(),
    });
    assert_eq!(large_bytes, 1_000);
    assert_eq!(small_bytes, 1_000);
    assert_eq!(stats.bytes, 2_000);
}

#[test]
fn admission_is_bounded_globally_and_per_flow() {
    let mut limits = config();
    limits.max_packets_per_flow = 1;
    limits.max_queued_packets = 2;
    let mut scheduler = Scheduler::new(limits).unwrap();
    let flow = FlowId::new(1);
    scheduler
        .enqueue(WorkClass::Data { flow, weight: 1 }, 10, 1)
        .unwrap();
    assert!(matches!(
        scheduler.enqueue(WorkClass::Data { flow, weight: 1 }, 10, 2),
        Err(EnqueueError::FlowQueueFull(2))
    ));
    scheduler.enqueue(WorkClass::Control, 10, 3).unwrap();
    assert!(matches!(
        scheduler.enqueue(WorkClass::Control, 10, 4),
        Err(EnqueueError::QueueFull(4))
    ));
    assert_eq!(scheduler.snapshot().queued_packets, 2);
}

#[test]
fn control_work_gets_reserved_service_before_payload() {
    let mut scheduler = Scheduler::new(config()).unwrap();
    scheduler
        .enqueue(
            WorkClass::Data {
                flow: FlowId::new(1),
                weight: 1,
            },
            100,
            "data",
        )
        .unwrap();
    scheduler.enqueue(WorkClass::Control, 10, "ack").unwrap();
    let mut order = Vec::new();
    let stats = scheduler.run_round(|_, value| order.push(value));
    assert_eq!(order, ["ack", "data"]);
    assert_eq!(stats.control_packets, 1);
}

#[test]
fn one_flow_cannot_exceed_contiguous_byte_budget() {
    let mut scheduler = Scheduler::new(config()).unwrap();
    let flow = FlowId::new(1);
    for item in 0..4 {
        scheduler
            .enqueue(WorkClass::Data { flow, weight: 4 }, 600, item)
            .unwrap();
    }
    let first = scheduler.run_round(|_, _| {});
    assert_eq!(first.packets, 1);
    assert_eq!(first.bytes, 600);
    assert_eq!(scheduler.snapshot().queued_packets, 3);
}

#[test]
fn processing_time_is_part_of_the_round_budget() {
    let mut limits = config();
    limits.max_time_per_round = Duration::from_millis(1);
    let mut scheduler = Scheduler::new(limits).unwrap();
    for item in 0..3 {
        scheduler.enqueue(WorkClass::Control, 10, item).unwrap();
    }
    let stats = scheduler.run_round(|_, _| std::thread::sleep(Duration::from_millis(2)));
    assert_eq!(stats.packets, 1);
    assert!(stats.time_budget_exhausted);
    assert_eq!(scheduler.snapshot().queued_packets, 2);
}

#[test]
fn an_exhausted_budget_still_processes_one_data_packet() {
    // A round whose start already exceeds the budget models a thread
    // preempted between taking the start time and visiting the first flow.
    let mut limits = config();
    limits.max_time_per_round = Duration::from_nanos(1);
    let mut scheduler = Scheduler::new(limits).unwrap();
    let flow = FlowId::new(7);
    for item in 0..3 {
        scheduler
            .enqueue(WorkClass::Data { flow, weight: 1 }, 10, item)
            .unwrap();
    }
    for remaining in (0..3).rev() {
        std::thread::sleep(Duration::from_micros(10));
        let stats = scheduler.run_round_limited(1, usize::MAX, |_, _| {});
        assert_eq!(stats.packets, 1);
        assert_eq!(scheduler.snapshot().queued_packets, remaining);
    }
}

#[test]
fn consumer_limit_preserves_the_undrained_suffix() {
    let mut scheduler = Scheduler::new(config()).unwrap();
    let flow = FlowId::new(1);
    for item in 0..5 {
        scheduler
            .enqueue(WorkClass::Data { flow, weight: 1 }, 100, item)
            .unwrap();
    }
    let mut values = Vec::new();
    let first = scheduler.run_round_limited(2, 250, |_, value| values.push(value));
    assert_eq!(first.packets, 2);
    assert_eq!(first.bytes, 200);
    assert_eq!(values, [0, 1]);
    assert_eq!(scheduler.snapshot().queued_packets, 3);

    let second = scheduler.run_round(|_, value| values.push(value));
    assert_eq!(second.packets, 3);
    assert_eq!(values, [0, 1, 2, 3, 4]);
    assert_eq!(scheduler.snapshot().queued_packets, 0);
}
