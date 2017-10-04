use std::panic;
use queue::FlowQueue;
use flow::*;
use protocol::Classify;
use super::*;

#[test]
fn new_flow_export_timeout_correct() {
    let customs   = Customs::new(&[]);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);

    let flow = flow(23, 31, true);
    let key  = flow.key();

    queue.add(flow.clone());

    let min  = flow.timestamp + Duration::seconds(0);
    let max  = flow.timestamp + Duration::seconds(15);
    let next = queue[&key].export;

    assert!(next >= min && next <= max);
}

#[test]
fn exported_counter_updated_on_add() {
    let customs   = Customs::new(&[]);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);

    let mut flow_a = flow(23, 31, true);
    let mut flow_b = flow_a.clone();
    let win = Default::default();

    flow_a.tos       = 1;
    flow_b.tos       = 2;
    flow_a.transport = Transport::TCP{seq: 61, flags: SYN, window: win};
    flow_b.transport = Transport::TCP{seq: 62, flags: ACK, window: win};

    queue.add(flow_a.clone());
    queue.add(flow_b.clone());

    let key = flow_a.key();
    let ctr = &queue[&key];

    assert_eq!(ctr.tos,       flow_a.tos|flow_b.tos);
    assert_eq!(ctr.tcp_flags, SYN|ACK);
    assert_eq!(ctr.packets,   (flow_a.packets + flow_b.packets) as u64);
    assert_eq!(ctr.fragments, (flow_a.fragments + flow_b.fragments) as u64);
    assert_eq!(ctr.bytes,     (flow_a.bytes + flow_b.bytes) as u64);
}

#[test]
fn unexported_counter_not_updated_on_add() {
    let customs   = Customs::new(&[]);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);

    let flow = flow(23, 31, false);
    let key  = flow.key();

    queue.add(flow);

    let ctr = &queue[&key];
    assert_eq!(ctr.tos,       0);
    assert_eq!(ctr.tcp_flags, 0);
    assert_eq!(ctr.packets,   0);
    assert_eq!(ctr.fragments, 0);
    assert_eq!(ctr.bytes,     0);
}

#[test]
#[should_panic(expected = "failed to send flow: Failed(2)")]
fn exported_flow_sent_on_decode() {
    let customs   = Customs::new(&CUSTOMS);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.direction = Direction::In;
        flow.export    = true;
        queue.add(flow);
    }
}

#[test]
#[should_panic(expected = "failed to send flow: Failed(2)")]
fn exported_flow_sent_on_export() {
    let customs   = Customs::new(&[]);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.direction = Direction::In;
        flow.export    = true;
        queue.add(flow);
    }
    queue.export(Timestamp::now());
}

#[test]
fn unexported_flow_not_sent_on_decode() {
    let customs   = Customs::new(&CUSTOMS);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.direction = Direction::In;
        flow.export    = false;
        queue.add(flow);
    }
}

#[test]
fn unexported_flow_not_sent_on_export() {
    let customs   = Customs::new(&[]);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.direction = Direction::In;
        flow.export    = false;
        queue.add(flow);
    }
    queue.export(Timestamp::now());
}

#[test]
fn customs_appended_on_decode() {
    let customs   = Customs::new(&CUSTOMS);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);
    for mut flow in iter::flows("pcaps/dns/google.com-any.pcap") {
        let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            flow.fragments = 2;
            flow.direction = Direction::Out;
            flow.export    = true;
            queue.add(flow);
        }));

        let customs = queue.customs();
        assert_eq!(Some(Value::U32(2)), value(FRAGMENTS, customs));
        customs.clear();
    }
}

#[test]
fn customs_appended_on_export() {
    let customs   = Customs::new(CUSTOMS);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);

    let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let flow = flow(32, 31, true);
        queue.add(flow);
        queue.export(Timestamp::now());
    }));

    let customs = queue.customs();
    assert_eq!(Some(Value::U32(17)), value(FRAGMENTS, customs));
}

#[test]
fn active_flows_retained_on_compact() {
    let customs   = Customs::new(CUSTOMS);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);

    let export = Timestamp::zero() + Duration::seconds(30);

    for (src, dst) in vec![(23, 31), (47, 53)] {
        let mut flow = flow(src, dst, false);
        flow.timestamp = export + Duration::seconds(1);
        flow.direction = Direction::In;
        queue.add(flow);
    }

    assert_eq!(2, queue.len());
    queue.export(export);
    assert_eq!(2, queue.len());
}

#[test]
fn expired_flows_removed_on_compact() {
    let customs   = Customs::new(CUSTOMS);
    let mut queue = FlowQueue::new(None, customs, Classify::new(), true);

    let export = Timestamp::zero() + Duration::seconds(30);

    for (src, dst) in vec![(23, 31), (47, 53)] {
        let mut flow = flow(src, dst, false);
        flow.direction = Direction::In;
        queue.add(flow);
    }

    assert_eq!(2, queue.len());
    queue.export(export);
    assert_eq!(0, queue.len());
}
