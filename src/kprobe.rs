use std::time::SystemTime;
use pnet::datalink::EthernetDataLinkChannelIterator;
use pnet::packet::{Packet as PacketExt};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use packet::{self, Packet};
use packet::Transport::*;
use protocol::{Message, parse_frontend, parse_backend};
use nom::IResult::*;
use flow::*;
use queue::FlowQueue;

pub struct Kprobe {
    ports: Option<Vec<u16>>,
    queue: FlowQueue,
}

impl Kprobe {
    pub fn new(ports: Option<Vec<u16>>) -> Kprobe {
        Kprobe {
            ports: ports,
            queue: FlowQueue::new(),
        }
    }

    pub fn run<'a>(&mut self, mut iter: Box<EthernetDataLinkChannelIterator + 'a>) {
        while let Ok(packet) = iter.next() {
            let ts = SystemTime::now();
            if let Some(pkt) = packet::decode(&packet) {
                // FIXME: ARP, RARP, VLAN, etc not handled
                match pkt.transport() {
                    Some(TCP(ref tcp)) => self.tcp(ts, &pkt, tcp),
                    Some(UDP(ref udp)) => self.udp(ts, &pkt, udp),
                    _                  => None,
                }.map(|flow| self.queue.add(flow));
                self.queue.flush();
            }
        }
    }

    fn tcp(&mut self, ts: SystemTime, p: &Packet, tcp: &TcpPacket) -> Option<Flow> {
        if !self.want(tcp.get_source(), tcp.get_destination()) {
            return None;
        }

        let payload = match (tcp.get_source(), tcp.get_destination()) {
            (_, 5432) => self.postgres_fe(tcp),
            (5432, _) => self.postgres_be(tcp),
            _         => None,
        };

        Some(Flow{
            timestamp: ts,
            protocol:  Protocol::TCP,
            src:       Addr{addr: p.src(), port: tcp.get_source()},
            dst:       Addr{addr: p.dst(), port: tcp.get_destination()},
            packets:   1,
            bytes:     tcp.payload().len(),
            payload:   payload,
        })
    }

    fn udp(&mut self, ts: SystemTime, p: &Packet, udp: &UdpPacket) -> Option<Flow> {
        if !self.want(udp.get_source(), udp.get_destination()) {
            return None;
        }

        Some(Flow{
            timestamp: ts,
            protocol:  Protocol::UDP,
            src:       Addr{addr: p.src(), port: udp.get_source()},
            dst:       Addr{addr: p.dst(), port: udp.get_destination()},
            packets:   1,
            bytes:     udp.payload().len(),
            payload:   None,
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

    fn postgres_fe(&mut self, p: &TcpPacket) -> Option<Vec<Payload>> {
        if let Done(_, msgs) = parse_frontend(p.payload()) {
            let mut vec = Vec::new();
            for msg in msgs {
                let maybe_query = match msg {
                    Message::Query(query)     => Some(query),
                    Message::Parse{query, ..} => Some(query),
                    _                         => None,
                };

                if let Some(q) = maybe_query {
                    vec.push(Payload::Postgres(Postgres::Query(q.to_owned())))
                }
            }
            return Some(vec)
        }
        None
    }

    fn postgres_be(&mut self, p: &TcpPacket) -> Option<Vec<Payload>> {
        if let Done(_, msgs) = parse_backend(p.payload()) {
            let mut vec = Vec::new();
            for msg in msgs {
                match msg {
                    Message::EmptyQueryResponse | Message::CommandComplete(..) |
                    Message::CloseComplete | Message::Error(..) => {
                        vec.push(Payload::Postgres(Postgres::QueryComplete));
                    }
                    _ => ()
                }
            }
            return Some(vec)
        }
        None
    }
}
