use std::borrow::Cow;
use std::mem::transmute;
use pcap::{Capture, Offline};
use pnet::packet::{Packet as PacketExt};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use crate::reasm::Reassembler;
use crate::flow::*;
use crate::packet::{self, Packet, Opaque};
use crate::packet::Transport::*;

pub struct FlowIterator<'a>  {
    capture: Capture<Offline>,
    asm:     Reassembler,
    payload: Cow<'a, [u8]>,
}

pub fn flows<'a>(path: &str) -> FlowIterator<'a> {
    static EMPTY: [u8; 0] = [];
    FlowIterator{
        capture: Capture::from_file(path).unwrap(),
        asm:     Reassembler::new(),
        payload: Cow::from(&EMPTY[..]),
    }
}

impl<'a> Iterator for FlowIterator<'a> {
    type Item = Flow<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Ok(pkt) = self.capture.next() {
            let ts = Timestamp(pkt.header.ts);
            if let Some(eth) = EthernetPacket::new(pkt.data) {
                if let (vlan, Some(pkt)) = packet::decode(&eth) {
                    if let Some(out) = self.asm.reassemble(ts, &pkt) {
                        let eth = Ethernet {
                            src:  eth.get_source(),
                            dst:  eth.get_destination(),
                            vlan: vlan,
                        };

                        let mut flow = unsafe {
                            self.payload = transmute(out.data);

                            match pkt.transport(&self.payload).unwrap() {
                                TCP(ref p)   => tcp(eth,  &pkt, transmute(p)),
                                UDP(ref p)   => udp(eth,  &pkt, transmute(p)),
                                ICMP(ref p)  => icmp(eth, &pkt, transmute(p)),
                                Other(ref o) => ip(eth,   &pkt, transmute(o)),
                            }
                        };

                        flow.timestamp = ts;
                        flow.packets   = out.packets;
                        flow.fragments = out.frags;
                        flow.bytes     = out.bytes;

                        return Some(flow);
                    }
                }
            }
        }
        None
    }
}

fn tcp<'a>(eth: Ethernet, p: &Packet, tcp: &'a TcpPacket) -> Flow<'a> {
    let seq    = tcp.get_sequence();
    let flags  = tcp.get_flags();
    let window = tcp_window(tcp);

    Flow{
        protocol:  Protocol::TCP,
        ethernet:  eth,
        src:       Addr{addr: p.src(), port: tcp.get_source()},
        dst:       Addr{addr: p.dst(), port: tcp.get_destination()},
        tos:       p.tos(),
        transport: Transport::TCP{ seq, flags, window },
        payload:   tcp.payload(),
        .. Default::default()
    }
}

fn udp<'a>(eth: Ethernet, p: &Packet, udp: &'a UdpPacket) -> Flow<'a> {
    Flow{
        protocol:  Protocol::UDP,
        ethernet:  eth,
        src:       Addr{addr: p.src(), port: udp.get_source()},
        dst:       Addr{addr: p.dst(), port: udp.get_destination()},
        tos:       p.tos(),
        transport: Transport::UDP,
        payload:   udp.payload(),
        .. Default::default()
    }
}

fn icmp<'a>(eth: Ethernet, p: &Packet, icmp: &'a IcmpPacket) -> Flow<'a> {
    let pack = ((icmp.get_icmp_type().0 as u16) << 8) | icmp.get_icmp_code().0 as u16;

    Flow{
        protocol:  Protocol::ICMP,
        ethernet:  eth,
        src:       Addr{addr: p.src(), port: 0   },
        dst:       Addr{addr: p.dst(), port: pack},
        tos:       p.tos(),
        transport: Transport::ICMP,
        payload:   icmp.payload(),
        .. Default::default()
    }
}

fn ip<'a>(eth: Ethernet, p: &Packet, o: &'a Opaque) -> Flow<'a> {
    Flow{
        protocol:  Protocol::Other(o.protocol),
        ethernet:  eth,
        src:       Addr{addr: p.src(), port: 0},
        dst:       Addr{addr: p.dst(), port: 0},
        tos:       p.tos(),
        transport: Transport::Other,
        payload:   o.payload,
        .. Default::default()
    }
}
