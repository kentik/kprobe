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
use reasm::Reassembler;
use queue::FlowQueue;
use libkflow::kflowCustom;

pub struct Kprobe {
    interface: NetworkInterface,
    asm:       Reassembler,
    queue:     FlowQueue,
}

impl Kprobe {
    pub fn new(interface: NetworkInterface, customs: Vec<kflowCustom>) -> Kprobe {
        Kprobe {
            interface: interface,
            asm:       Reassembler::new(),
            queue:     FlowQueue::new(customs),
        }
    }

    pub fn run(&mut self, mut cap: Capture<Active>) -> Result<(), Error>{
        loop {
            match cap.next() {
                Ok(packet)          => self.record(packet),
                Err(TimeoutExpired) => self.queue.flush(Timestamp::now()),
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

            let ts = Timestamp(packet.header.ts);

            if let Some((frags, payload)) = self.asm.reassemble(ts, &pkt) {
                if let Some(transport) = pkt.transport(&payload) {
                    let mut flow = match transport {
                        TCP(ref tcp)   => self.tcp(eth, &pkt, tcp),
                        UDP(ref udp)   => self.udp(eth, &pkt, udp),
                        ICMP(ref icmp) => self.icmp(eth, &pkt, icmp),
                        Other(ref o)   => self.ip(eth, &pkt, o),
                    };

                    flow.timestamp  = ts;
                    flow.fragments += frags;

                    self.queue.add(dir, flow);
                    self.queue.flush(ts);
                    self.asm.flush(ts);
                }
            }
        }
    }

    fn tcp<'a>(&self, eth: Ethernet, p: &Packet, tcp: &'a TcpPacket) -> Flow<'a> {
        Flow{
            protocol:  Protocol::TCP,
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: tcp.get_source()},
            dst:       Addr{addr: p.dst(), port: tcp.get_destination()},
            tos:       p.tos(),
            transport: Transport::TCP{ flags: tcp.get_flags() },
            bytes:     p.len(),
            payload:   tcp.payload(),
            .. Default::default()
        }
    }

    fn udp<'a>(&self, eth: Ethernet, p: &Packet, udp: &'a UdpPacket) -> Flow<'a> {
        Flow{
            protocol:  Protocol::UDP,
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: udp.get_source()},
            dst:       Addr{addr: p.dst(), port: udp.get_destination()},
            tos:       p.tos(),
            transport: Transport::UDP,
            bytes:     p.len(),
            payload:   udp.payload(),
            .. Default::default()
        }
    }

    fn icmp<'a>(&self, eth: Ethernet, p: &Packet, icmp: &'a IcmpPacket) -> Flow<'a> {
        let pack = ((icmp.get_icmp_type().0 as u16) << 8) | icmp.get_icmp_code().0 as u16;

        Flow{
            protocol:  Protocol::ICMP,
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: 0   },
            dst:       Addr{addr: p.dst(), port: pack},
            tos:       p.tos(),
            transport: Transport::ICMP,
            bytes:     p.len(),
            payload:   icmp.payload(),
            .. Default::default()
        }
    }

    fn ip<'a>(&self, eth: Ethernet, p: &Packet, o: &'a Opaque) -> Flow<'a> {
        Flow{
            protocol:  Protocol::Other(o.protocol),
            ethernet:  eth,
            src:       Addr{addr: p.src(), port: 0},
            dst:       Addr{addr: p.dst(), port: 0},
            tos:       p.tos(),
            transport: Transport::Other,
            bytes:     p.len(),
            payload:   o.payload,
            .. Default::default()
        }
    }
}
