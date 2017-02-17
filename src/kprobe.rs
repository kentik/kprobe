use std::time::SystemTime;
use pnet::datalink::EthernetDataLinkChannelIterator;
use pnet::datalink::NetworkInterface;
use pnet::packet::{Packet as PacketExt};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use packet::{self, Packet};
use packet::Transport::*;
use flow::*;
use queue::{FlowQueue, Direction};

pub struct Kprobe {
    interface: NetworkInterface,
    ports:     Option<Vec<u16>>,
    queue:     FlowQueue,
}

impl Kprobe {
    pub fn new(interface: NetworkInterface, ports: Option<Vec<u16>>) -> Kprobe {
        Kprobe {
            interface: interface,
            ports:     ports,
            queue:     FlowQueue::new(),
        }
    }

    pub fn run<'a>(&mut self, mut iter: Box<EthernetDataLinkChannelIterator + 'a>) {
        while let Ok(packet) = iter.next() {
            let ts = SystemTime::now();
            if let Some(pkt) = packet::decode(&packet) {
                let eth = Ethernet {
                    src: packet.get_source(),
                    dst: packet.get_destination(),
                };

                let dir = match self.interface.mac {
                    Some(mac) if mac == eth.dst => Direction::In,
                    Some(mac) if mac == eth.src => Direction::Out,
                    _                           => Direction::Unknown,
                };

                // FIXME: ARP, RARP, VLAN, etc not handled
                match pkt.transport() {
                    Some(TCP(ref tcp))   => self.tcp(ts, eth, &pkt, tcp),
                    Some(UDP(ref udp))   => self.udp(ts, eth, &pkt, udp),
                    Some(ICMP(ref icmp)) => self.icmp(ts, eth, &pkt, icmp),
                    _                    => None,
                }.map(|flow| self.queue.add(dir, flow));
                self.queue.flush();
            }
        }
    }

    fn tcp<'a>(&mut self, ts: SystemTime, eth: Ethernet, p: &Packet, tcp: &'a TcpPacket) -> Option<Flow<'a>> {
        if !self.want(tcp.get_source(), tcp.get_destination()) {
            return None;
        }

        Some(Flow{
            timestamp: ts,
            protocol:  Protocol::TCP,
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: tcp.get_source()},
            dst:       Addr{addr: p.dst(), port: tcp.get_destination()},
            tos:       p.tos(),
            transport: Transport::TCP{ flags: tcp.get_flags() },
            bytes:     p.len(),
            payload:   tcp.payload(),
        })
    }

    fn udp<'a>(&mut self, ts: SystemTime, eth: Ethernet, p: &Packet, udp: &'a UdpPacket) -> Option<Flow<'a>> {
        if !self.want(udp.get_source(), udp.get_destination()) {
            return None;
        }

        Some(Flow{
            timestamp: ts,
            protocol:  Protocol::UDP,
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: udp.get_source()},
            dst:       Addr{addr: p.dst(), port: udp.get_destination()},
            tos:       p.tos(),
            transport: Transport::UDP,
            bytes:     p.len(),
            payload:   udp.payload(),
        })
    }

    fn icmp<'a>(&mut self, ts: SystemTime, eth: Ethernet, p: &Packet, icmp: &'a IcmpPacket) -> Option<Flow<'a>> {
        Some(Flow{
            timestamp: ts,
            protocol:  Protocol::ICMP,
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: 0},
            dst:       Addr{addr: p.dst(), port: 0},
            tos:       p.tos(),
            transport: Transport::ICMP,
            bytes:     p.len(),
            payload:   icmp.payload(),
        })
    }

    fn want(&self, src: u16, dst: u16) -> bool {
        if self.ports.is_none() {
            return true
        }

        self.ports.as_ref().map_or(false, |ps| {
            ps.iter().any(|p| *p == src || *p == dst)
        })
    }

}
