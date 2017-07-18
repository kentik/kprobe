mod iter;
mod decoders;

use pcap::Capture;
use pnet::packet::{Packet as PacketExt, PacketSize};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use flow::*;
use packet;
use reasm::Reassembler;
use track::Tracker;

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

#[test]
fn test_udp_application_latency() {
    let mut trk = Tracker::new(&[]);

    for flow in iter::flows("pcaps/dns/google.com-any.pcap") {
        trk.add(&flow);
    }

    let src = Addr{addr: "10.0.0.52".parse().unwrap(), port: 52407};
    let dst = Addr{addr: "8.8.4.4".parse().unwrap(),   port: 53   };
    let key = Key(Protocol::UDP, src, dst);

    assert_eq!(Some(44), trk.latency(&key).map(|d| d.num_milliseconds()));
}

#[test]
fn test_tcp_application_latency() {
    let mut trk = Tracker::new(&[]);

    for flow in iter::flows("pcaps/http/google.com.pcap") {
        if flow.tcp_flags() & FIN == FIN {
            break;
        }
        trk.add(&flow);
    }

    let src = Addr{addr: "10.211.55.16".parse().unwrap(),   port: 42370};
    let dst = Addr{addr: "172.217.25.110".parse().unwrap(), port: 80   };
    let key = Key(Protocol::TCP, src, dst);

    assert_eq!(Some(7), trk.latency(&key).map(|d| d.num_milliseconds()));
}

#[test]
fn test_ignore_ipv4_ethernet_padding() {
    let mut cap = Capture::from_file("pcaps/ip/ipv4_eth_padding.pcap").unwrap();

    while let Ok(pkt) = cap.next() {
        let eth = EthernetPacket::new(pkt.data).unwrap();
        let ip  = Ipv4Packet::new(eth.payload()).unwrap();
        let pkt = packet::decode(&eth).1.unwrap();

        let tcp = match pkt.transport(ip.payload()) {
            Some(packet::Transport::TCP(tcp)) => tcp,
            _                                 => unreachable!(),
        };

        assert_eq!(0, tcp.payload().len());
    }
}
