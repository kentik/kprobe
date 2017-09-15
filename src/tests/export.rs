use std::net::IpAddr;
use std::panic;
use protocol::Decoders;
use queue::FlowQueue;
use flow::*;
use super::*;

#[test]
fn new_flow_export_timeout_correct() {
    let customs   = &[];
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);

    let flow = flow(23, 31, true);
    let key  = flow.key();

    queue.add(Direction::Out, flow.clone());

    let min  = flow.timestamp + Duration::seconds(0);
    let max  = flow.timestamp + Duration::seconds(15);
    let next = queue[&key].export;

    assert!(next >= min && next <= max);
}

#[test]
fn exported_counter_updated_on_add() {
    let customs   = &[];
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);

    let mut flow_a = flow(23, 31, true);
    let mut flow_b = flow_a.clone();
    let win = Default::default();

    flow_a.tos       = 1;
    flow_b.tos       = 2;
    flow_a.transport = Transport::TCP{seq: 61, flags: SYN, window: win};
    flow_b.transport = Transport::TCP{seq: 62, flags: ACK, window: win};

    queue.add(Direction::Out, flow_a.clone());
    queue.add(Direction::Out, flow_b.clone());

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
    let customs   = &[];
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);

    let flow = flow(23, 31, false);
    let key  = flow.key();

    queue.add(Direction::Out, flow);

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
    let customs   = CUSTOMS;
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.export = true;
        queue.add(Direction::In, flow);
    }
}

#[test]
#[should_panic(expected = "failed to send flow: Failed(2)")]
fn exported_flow_sent_on_export() {
    let customs   = &[];
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.export = true;
        queue.add(Direction::In, flow);
    }
    queue.export(Timestamp::now());
}

#[test]
fn unexported_flow_not_sent_on_decode() {
    let customs   = CUSTOMS;
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.export = false;
        queue.add(Direction::In, flow);
    }
}

#[test]
fn unexported_flow_not_sent_on_export() {
    let customs   = &[];
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.export = false;
        queue.add(Direction::In, flow);
    }
    queue.export(Timestamp::now());
}

#[test]
fn customs_appended_on_decode() {
    let customs   = CUSTOMS;
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);
    for mut flow in iter::flows("pcaps/dns/google.com-any.pcap") {
        let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            flow.fragments = 2;
            flow.export    = true;
            queue.add(Direction::Out, flow);
        }));

        let customs = queue.customs();
        assert_eq!(Some(Value::U32(2)), value("FRAGMENTS", customs));
        customs.clear();
    }
}

#[test]
fn customs_appended_on_export() {
    let customs   = CUSTOMS;
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);

    let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let flow = flow(32, 31, true);
        queue.add(Direction::Out, flow);
        queue.export(Timestamp::now());
    }));

    let customs = queue.customs();
    assert_eq!(Some(Value::U32(17)), value("FRAGMENTS", customs));
}

#[test]
fn active_flows_retained_on_compact() {
    let customs   = CUSTOMS;
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);

    let export = Timestamp::zero() + Duration::seconds(30);

    for (src, dst) in vec![(23, 31), (47, 53)] {
        let mut flow = flow(src, dst, false);
        flow.timestamp = export + Duration::seconds(1);
        queue.add(Direction::In, flow);
    }

    assert_eq!(2, queue.len());
    queue.export(export);
    assert_eq!(2, queue.len());
}

#[test]
fn expired_flows_removed_on_compact() {
    let customs   = CUSTOMS;
    let decoders  = Decoders::new(customs);
    let mut queue = FlowQueue::new(None, customs, decoders);

    let export = Timestamp::zero() + Duration::seconds(30);

    for (src, dst) in vec![(23, 31), (47, 53)] {
        let flow = flow(src, dst, false);
        queue.add(Direction::In, flow);
    }

    assert_eq!(2, queue.len());
    queue.export(export);
    assert_eq!(0, queue.len());
}

fn flow<'a>(src: u32, dst: u32, export: bool) -> Flow<'a> {
    Flow{
        timestamp: Timestamp::zero(),
        ethernet:  Ethernet{
            src:  "00:01:02:03:04:05".parse().unwrap(),
            dst:  "00:0a:0b:0c:0d:0e".parse().unwrap(),
            vlan:  None,
        },
        protocol:  Protocol::TCP,
        src:       Addr{addr: IpAddr::V4(src.into()), port: src as u16},
        dst:       Addr{addr: IpAddr::V4(dst.into()), port: dst as u16},
        tos:       7,
        transport: Transport::TCP{seq: 11, flags: SYN, window: Default::default()},
        packets:   13,
        fragments: 17,
        bytes:     19,
        export:    export,
        ..Default::default()
    }
}
