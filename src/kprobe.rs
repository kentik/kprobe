use pcap::{self, Capture, Active, Error};
use pcap::Error::*;
use pnet::datalink::NetworkInterface;
use pnet::packet::{Packet as PacketExt};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use crate::config::Config;
use crate::packet::{self, Packet, Opaque};
use crate::packet::Transport::*;
use crate::flow::*;
use crate::reasm::Reassembler;
use crate::sample::Sampler;
use crate::sample::Accept::*;
use crate::time::Timestamp;
use crate::translate::Translate;
use crate::queue::FlowQueue;

pub struct Kprobe {
    interface:  NetworkInterface,
    sampler:    Option<Sampler>,
    translate:  Option<Translate>,
    asm:        Reassembler,
    queue:      FlowQueue,
}

impl Kprobe {
    pub fn new(interface: NetworkInterface, mut cfg: Config) -> Kprobe {
        Kprobe {
            interface: interface,
            sampler:   cfg.sampler(),
            translate: cfg.translate(),
            asm:       Reassembler::new(),
            queue:     cfg.queue(),
        }
    }

    pub fn run(&mut self, mut cap: Capture<Active>) -> Result<(), Error> {
        loop {
            match cap.next() {
                Ok(packet)          => self.record(packet),
                Err(TimeoutExpired) => self.queue.export(Timestamp::now()),
                Err(NoMorePackets)  => return Ok(()),
                Err(e)              => return Err(e),
            }
        }
    }

    pub fn record<'a>(&mut self, packet: pcap::Packet<'a>) {
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

            let ts = Timestamp::from(packet.header.ts);

            if let Some(out) = self.asm.reassemble(ts, &pkt) {
                if let Some(transport) = pkt.transport(&out.data) {
                    let mut flow = match transport {
                        TCP(ref tcp)   => self.tcp(eth, &pkt, tcp),
                        UDP(ref udp)   => self.udp(eth, &pkt, udp),
                        ICMP(ref icmp) => self.icmp(eth, &pkt, icmp),
                        Other(ref o)   => self.ip(eth, &pkt, o),
                    };

                    flow.timestamp = ts;
                    flow.packets   = out.packets;
                    flow.fragments = out.frags;
                    flow.bytes     = out.bytes;
                    flow.direction = dir;
                    flow.export    = true;

                    if let Some(ref s) = self.sampler {
                        match s.accept(&flow) {
                            Export => flow.export = true,
                            Decode => flow.export = false,
                            Ignore => return,
                        }
                    }

                    if let Some(ref t) = self.translate {
                        t.translate(&mut flow);
                    }

                    self.queue.add(flow);
                    self.queue.export(ts);
                    self.asm.flush(ts);
                }
            }
        }
    }

    fn tcp<'a>(&self, eth: Ethernet, p: &Packet, tcp: &'a TcpPacket) -> Flow<'a> {
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

    fn udp<'a>(&self, eth: Ethernet, p: &Packet, udp: &'a UdpPacket) -> Flow<'a> {
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

    fn icmp<'a>(&self, eth: Ethernet, p: &Packet, icmp: &'a IcmpPacket) -> Flow<'a> {
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

    fn ip<'a>(&self, eth: Ethernet, p: &Packet, o: &'a Opaque) -> Flow<'a> {
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
}
