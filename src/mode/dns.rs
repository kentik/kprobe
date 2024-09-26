use std::mem::swap;
use std::net::IpAddr;
use anyhow::Result;
use log::{debug, warn};
use nom::IResult::Done;
use pcap::{Capture, Active};
use pcap::Error::*;
use pnet::packet::{Packet as PacketExt};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use time::Duration;
use kentik_api::dns::*;
use crate::flow::Addr;
use crate::packet::{self, Packet, Transport::*};
use crate::protocol::dns::parser::{self, Rdata};
use crate::reasm::Reassembler;
use crate::time::Timestamp;

pub struct Dns {
    asm:    Reassembler,
    buffer: Vec<Response>,
    client: Client,
    last:   Timestamp,
}

pub fn run(
    cap: Capture<Active>,
    client: Client,
    filter_expr: Option<String>,
) -> Result<()> {
    run_base(cap, client, filter_expr, Dns::plain_parse)
}

pub fn run_juniper(
    cap: Capture<Active>,
    client: Client,
    filter_expr: Option<String>,
) -> Result<()> {
    run_base(cap, client, filter_expr, Dns::parse_stripped)
}

pub fn run_base<F>(mut cap: Capture<Active>, client: Client, filter_expr: Option<String>, mut parser: F) -> Result<()>
where F: FnMut(&mut Dns, Addr, Addr, & [u8], Timestamp)
{
    let mut dns = Dns::new(client);

    let filter_expr = filter_expr.unwrap_or("udp src port 53 or ip[6:2] & 0x1fff != 0x0000".to_owned());
    cap.filter(&filter_expr, true)?;

    loop {
        match cap.next_packet() {
            Ok(packet) => dns.record(packet, &mut parser),
            Err(TimeoutExpired) => dns.flush(Timestamp::now()),
            Err(NoMorePackets)  => return Ok(()),
            Err(e)              => return Err(e.into()),
        }
    }
}

impl Dns {
    pub fn new(client: Client) -> Self {
        Dns {
            asm:    Reassembler::new(),
            buffer: Vec::with_capacity(1024),
            client: client,
            last:   Timestamp::zero(),
        }
    }

    pub fn record<'a, F>(&mut self, packet: pcap::Packet<'a>, consumer: &mut F)
    where F: FnMut(&mut Self, Addr, Addr, & [u8], Timestamp),
    {
        let eth = match EthernetPacket::new(packet.data) {
            Some(pkt) => pkt,
            None => return,
        };

        if let (_vlan, Some(pkt)) = packet::decode(&eth) {
            let ts = Timestamp::from(packet.header.ts);

            if let Some(out) = self.asm.reassemble(ts, &pkt) {
                if let Some(transport) = pkt.transport(&out.data) {
                    let (src, dst, payload) = match transport {
                        TCP(ref tcp) => self.tcp(&pkt, tcp),
                        UDP(ref udp) => self.udp(&pkt, udp),
                        _ => return,
                    };

                    consumer(self, src, dst, payload, ts);
                }
            }

            self.flush(ts);
        }
    }

    pub fn plain_parse(&mut self, src: Addr, dst: Addr, payload: &[u8], _ts: Timestamp) {
        self.parse(src, dst, payload).map(|r| {
            self.buffer.push(r);
        });
    }

    pub fn parse_stripped(&mut self, _src: Addr, _dst: Addr, payload: &[u8], ts: Timestamp) {
        let pkt = packet::decode_from_l3(&payload[8..]);
        if pkt.is_none() {
            return
        }
        let pkt = pkt.unwrap();

        if let Some(out) = self.asm.reassemble(ts, &pkt) {
            if let Some(transport) = pkt.transport(&out.data) {
                let (src, dst, payload) = match transport {
                    TCP(ref tcp) => self.tcp(&pkt, tcp),
                    UDP(ref udp) => self.udp(&pkt, udp),
                    _ => return,
                };

                self.plain_parse(src, dst, payload, ts);
            }
        }
    }

    pub fn parse(&mut self, _src: Addr, dst: Addr, payload: &[u8]) -> Option<Response> {
        let mut msg = match parser::parse_message(payload) {
            Done(_, msg) => msg,
            _            => return None,
        };

        // msg.header.qr == 1 -> dns reply
        // msg.header.opcode == 0 -> standard query
        // msg.answer.is_empty() -> nothing to look at
        if msg.header.qr != 1 || msg.header.opcode != 0 || msg.answer.is_empty() {
            return None;
        }

        msg.query.pop().map(|qq| {
            let answers = msg.answer.iter().flat_map(|rr| {
                let name  = String::new();
                let cname = String::new();
                let ttl   = rr.ttl;
                match rr.rdata {
                    Rdata::A(ip)    => Some(Answer{name, cname, ip: addr(IpAddr::V4(ip)), ttl}),
                    Rdata::Aaaa(ip) => Some(Answer{name, cname, ip: addr(IpAddr::V6(ip)), ttl}),
                    _               => None,
                }
            }).collect();

            Response {
                question: Question{
                    name: qq.qname,
                    host: addr(dst.addr),
                    port: dst.port,
                },
                answers:  answers,
            }
        })
    }

    fn flush(&mut self, ts: Timestamp) {
        if (ts - self.last) >= Duration::seconds(1) {
            let mut rs = Vec::with_capacity(self.buffer.len());
            swap(&mut self.buffer, &mut rs);

            let timeout = Duration::milliseconds(10).unsigned_abs();
            let len = rs.len();
            match self.client.send(rs, timeout) {
                Ok(..) => debug!("DNS batch sent: {}", len),
                Err(e) => warn!("DNS queue full: {:?}", e),
            };

            self.asm.flush(ts);
            self.last = ts;
        }
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

fn addr(ip: IpAddr) -> Address {
    Address(ip)
}
