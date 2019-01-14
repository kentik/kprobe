use std::marker::PhantomData;
use std::net::{self, Ipv4Addr, Ipv6Addr};
use nom::IResult::Done;
use pcap::{Capture, Active};
use pcap::Error::*;
use pnet::packet::{Packet as PacketExt};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use args::Error;
use packet::{self, Packet, Transport::*};
use protocol::dns::parser::{self, Rdata};
use reasm::Reassembler;
use flow::{Addr, Timestamp};
use libkflow::*;

#[derive(Debug)]
pub struct Query {
    client: IpAddr,
    query:  String,
    answer: Vec<Answer>,
}

#[derive(Debug)]
pub struct Answer {
    addr: IpAddr,
    ttl:  u32,
}

#[derive(Debug)]
pub enum IpAddr {
    V4([u8;  4]),
    V6([u8; 16]),
}

struct Dns {
    asm: Reassembler,
}

pub fn run(mut cap: Capture<Active>) -> Result<(), Error<'static>> {
    let mut dns = Dns::new();

    cap.filter("udp src port 53")?;

    loop {
        match cap.next() {
            Ok(packet)          => dns.record(packet),
            Err(TimeoutExpired) => (),
            Err(NoMorePackets)  => return Ok(()),
            Err(e)              => return Err(e.into()),
        }
    }
}

impl Dns {
    fn new() -> Self {
        Dns {
            asm: Reassembler::new(),
        }
    }

    pub fn record<'a>(&mut self, packet: pcap::Packet<'a>) {
        let eth = match EthernetPacket::new(packet.data) {
            Some(pkt) => pkt,
            None      => return,
        };

        if let (_vlan, Some(pkt)) = packet::decode(&eth) {
            let ts = Timestamp(packet.header.ts);

            if let Some(out) = self.asm.reassemble(ts, &pkt) {
                if let Some(transport) = pkt.transport(&out.data) {
                    let (src, dst, payload) = match transport {
                        TCP(ref tcp)   => self.tcp(&pkt, tcp),
                        UDP(ref udp)   => self.udp(&pkt, udp),
                        _              => return,
                    };

                    if let Some(query) = self.parse(src, dst, payload) {
                        let kq: kflowDomainQuery = (&query).into();
                        let ka = query.answer.iter().map(|a| {
                            a.into()
                        }).collect::<Vec<_>>();

                        sendDNS(kq, &ka);
                    }
                }
            }
        }
    }

    pub fn parse(&mut self, _src: Addr, dst: Addr, payload: &[u8]) -> Option<Query> {
        let mut msg = match parser::parse_message(payload) {
            Done(_, mut msg) => msg,
            _                => return None,
        };

        if msg.header.qr != 1 || msg.header.opcode != 0 || msg.answer.is_empty() {
            return None;
        }

        msg.query.pop().map(|qq| {
            let answer = msg.answer.iter().flat_map(|rr| {
                match rr.rdata {
                    Rdata::A(ip)    => Some(Answer{addr: ip.into(), ttl: rr.ttl}),
                    Rdata::Aaaa(ip) => Some(Answer{addr: ip.into(), ttl: rr.ttl}),
                    _               => None,
                }
            }).collect();

            Query {
                client: dst.addr.into(),
                query:  qq.qname,
                answer: answer
            }
        })
    }

    fn tcp<'a>(&self, p: &Packet, tcp: &'a TcpPacket) -> (Addr, Addr, &'a [u8]) {
        let src = Addr{addr: p.src(), port: tcp.get_source()};
        let dst = Addr{addr: p.dst(), port: tcp.get_destination()};
        (src, dst, tcp.payload())
    }

    fn udp<'a>(&self, p: &Packet, udp: &'a UdpPacket) -> (Addr, Addr, &'a [u8]) {
        let src = Addr{addr: p.src(), port: udp.get_source()};
        let dst = Addr{addr: p.dst(), port: udp.get_destination()};
        (src, dst, udp.payload())
    }
}

impl From<net::IpAddr> for IpAddr {
    fn from(ip: net::IpAddr) -> Self {
        match ip {
            net::IpAddr::V4(ip) => IpAddr::V4(ip.octets()),
            net::IpAddr::V6(ip) => IpAddr::V6(ip.octets()),
        }
    }
}

impl From<Ipv4Addr> for IpAddr {
    fn from(ip: Ipv4Addr) -> Self {
        IpAddr::V4(ip.octets())
    }
}

impl From<Ipv6Addr> for IpAddr {
    fn from(ip: Ipv6Addr) -> Self {
        IpAddr::V6(ip.octets())
    }
}

impl<'a> From<&'a IpAddr> for kflowByteSlice<'a> {
    fn from(ip: &'a IpAddr) -> Self {
        let (ptr, len) = match ip {
            IpAddr::V4(ip) => (ip.as_ptr(), ip.len()),
            IpAddr::V6(ip) => (ip.as_ptr(), ip.len()),
        };

        Self {
            ptr: ptr,
            len: len,
            ptd: PhantomData,
        }
    }
}

impl<'a> From<&'a Query> for kflowDomainQuery<'a> {
    fn from(q: &'a Query) -> Self {
        Self {
            name: q.query.as_str().into(),
            host: (&q.client).into(),
        }
    }
}

impl<'a> From<&'a Answer> for kflowDomainAnswer<'a> {
    fn from(a: &'a Answer) -> Self {
        Self {
            ip:  (&a.addr).into(),
            ttl: a.ttl,
        }
    }
}
