use libc::timeval;
use pcap::{self, Capture, Active, Error};
use pcap::Error::*;
use pnet::datalink::NetworkInterface;
use pnet::packet::{Packet as PacketExt};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use packet::{self, Packet, Opaque};
use packet::Transport::*;
use flow::*;
use queue::FlowQueue;

pub struct Kprobe {
    interface: NetworkInterface,
    queue:     FlowQueue,
}

impl Kprobe {
    pub fn new(interface: NetworkInterface) -> Kprobe {
        Kprobe {
            interface: interface,
            queue:     FlowQueue::new(),
        }
    }

    pub fn run(&mut self, mut cap: Capture<Active>) -> Result<(), Error>{
        loop {
            match cap.next() {
                Ok(packet)          => self.record(packet),
                Err(TimeoutExpired) => self.queue.flush(),
                Err(NoMorePackets)  => return Ok(()),
                Err(e)              => return Err(e),
            }
        }
    }

    fn record<'a>(&mut self, packet: pcap::Packet<'a>) {
        let eth = match EthernetPacket::new(packet.data) {
            Some(pkt) => pkt,
            None      => return,
        };

        if let (vlan, Some(pkt)) = packet::decode(&eth) {
            let eth = Ethernet {
                src:  eth.get_source(),
                dst:  eth.get_destination(),
                vlan: vlan,
            };

            let dir = match self.interface.mac {
                Some(mac) if mac == eth.dst => Direction::In,
                Some(mac) if mac == eth.src => Direction::Out,
                _                           => Direction::Unknown,
            };

            if let Some(transport) = pkt.transport() {
                let ts = packet.header.ts;
                let flow = match transport {
                    TCP(ref tcp)   => self.tcp(ts, eth, &pkt, tcp),
                    UDP(ref udp)   => self.udp(ts, eth, &pkt, udp),
                    ICMP(ref icmp) => self.icmp(ts, eth, &pkt, icmp),
                    Other(ref o)   => self.ip(ts, eth, &pkt, o),
                };
                self.queue.add(dir, flow);
                self.queue.flush();
            }
        }
    }

    fn tcp<'a>(&self, ts: timeval, eth: Ethernet, p: &Packet, tcp: &'a TcpPacket) -> Flow<'a> {
        Flow{
            timestamp: ts,
            protocol:  Protocol::TCP,
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: tcp.get_source()},
            dst:       Addr{addr: p.dst(), port: tcp.get_destination()},
            tos:       p.tos(),
            transport: Transport::TCP{ flags: tcp.get_flags() },
            bytes:     p.len(),
            payload:   tcp.payload(),
        }
    }

    fn udp<'a>(&self, ts: timeval, eth: Ethernet, p: &Packet, udp: &'a UdpPacket) -> Flow<'a> {
        Flow{
            timestamp: ts,
            protocol:  Protocol::UDP,
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: udp.get_source()},
            dst:       Addr{addr: p.dst(), port: udp.get_destination()},
            tos:       p.tos(),
            transport: Transport::UDP,
            bytes:     p.len(),
            payload:   udp.payload(),
        }
    }

    fn icmp<'a>(&self, ts: timeval, eth: Ethernet, p: &Packet, icmp: &'a IcmpPacket) -> Flow<'a> {
        let pack = ((icmp.get_icmp_type().0 as u16) << 8) | icmp.get_icmp_code().0 as u16;

        Flow{
            timestamp: ts,
            protocol:  Protocol::ICMP,
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: 0   },
            dst:       Addr{addr: p.dst(), port: pack},
            tos:       p.tos(),
            transport: Transport::ICMP,
            bytes:     p.len(),
            payload:   icmp.payload(),
        }
    }

    fn ip<'a>(&self, ts: timeval, eth: Ethernet, p: &Packet, o: &'a Opaque) -> Flow<'a> {
        Flow{
            timestamp: ts,
            protocol:  Protocol::Other(o.protocol),
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: 0},
            dst:       Addr{addr: p.dst(), port: 0},
            tos:       p.tos(),
            transport: Transport::Other,
            bytes:     p.len(),
            payload:   o.payload,
        }
    }
}
