use queue::FlowQueue;
use flow::*;
use super::*;

#[test]
#[should_panic(expected = "failed to send flow: Failed(2)")]
fn exported_flow_sent_on_decode() {
    let mut queue = FlowQueue::new(None, CUSTOMS.to_vec());
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.export = true;
        queue.add(Direction::In, flow);
    }
}

#[test]
#[should_panic(expected = "failed to send flow: Failed(2)")]
fn exported_flow_sent_on_flush() {
    let mut queue = FlowQueue::new(None, Vec::new());
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.export = true;
        queue.add(Direction::In, flow);
    }
    queue.flush(Timestamp::now());
}

#[test]
fn unexported_flow_not_sent_on_decode() {
    let mut queue = FlowQueue::new(None, CUSTOMS.to_vec());
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.export = false;
        queue.add(Direction::In, flow);
    }
}

#[test]
fn unexported_flow_not_sent_on_flush() {
    let mut queue = FlowQueue::new(None, Vec::new());
    for mut flow in iter::flows("pcaps/http/google.com.pcap") {
        flow.export = false;
        queue.add(Direction::In, flow);
    }
    queue.flush(Timestamp::now());
}
