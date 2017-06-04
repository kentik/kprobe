use pcap::{Capture};
use pnet::packet::PacketSize;
use pnet::packet::ethernet::EthernetPacket;
use flow::Timestamp;
use packet;
use reasm::Reassembler;

#[test]
fn test_reassemble_single() {
    let mut cap = Capture::from_file("pcaps/dns/sns-pb.isc.org.pcap").unwrap();
    let mut asm = Reassembler::new();

    while let Ok(pkt) = cap.next() {
        let ts  = Timestamp(pkt.header.ts);
        let eth = EthernetPacket::new(pkt.data).unwrap();
        let len = pkt.header.len as usize - eth.packet_size();

        let pkt = packet::decode(&eth).1.unwrap();
        let out = asm.reassemble(ts, &pkt).unwrap();

        assert_eq!(out.packets, 1);
        assert_eq!(out.frags,   0);
        assert_eq!(out.bytes,   len);
    }
}

#[test]
fn test_reassemble_fragmented() {
    let mut cap = Capture::from_file("pcaps/dns/sns-pb.isc.org-dnssec.pcap").unwrap();
    let mut asm = Reassembler::new();

    cap.next().unwrap();

    let mut packets = 0;
    let mut frags   = 0;
    let mut bytes   = 0;
    let mut done    = false;

    while let Ok(pkt) = cap.next() {
        let ts  = Timestamp(pkt.header.ts);
        let eth = EthernetPacket::new(pkt.data).unwrap();
        let len = pkt.header.len as usize - eth.packet_size();

        packets += 1;
        frags   += 1;
        bytes   += len;

        let pkt = packet::decode(&eth).1.unwrap();

        if let Some(out) = asm.reassemble(ts, &pkt) {
            assert_eq!(out.packets, packets);
            assert_eq!(out.frags,   frags);
            assert_eq!(out.bytes,   bytes);
            done = true;
        }
    }

    assert!(done);
}
