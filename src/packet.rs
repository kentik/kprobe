use std::net::{IpAddr, Ipv4Addr};
use std::cmp::min;

use pnet::packet::{Packet as PacketExt, PacketSize};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;

#[derive(Debug)]
pub enum Packet<'a> {
    IPv4(Ipv4Packet<'a>),
    IPv6(Ipv6Packet<'a>),
    Other(Opaque<'a>),
}

#[derive(Debug)]
pub enum Transport<'a> {
    ICMP(IcmpPacket<'a>),
    TCP(TcpPacket<'a>),
    UDP(UdpPacket<'a>),
    Other(Opaque<'a>),
}

#[derive(Debug)]
pub struct Opaque<'a> {
    pub protocol: u16,
    pub payload:  &'a [u8],
}

pub fn decode<'a>(p: &'a EthernetPacket<'a>) -> (Option<u16>, Option<Packet<'a>>) {
    let mut ethertype = p.get_ethertype();
    let mut payload   = p.payload();
    let mut vlan      = None;

    while ethertype == EtherTypes::Vlan {
        if let Some(pkt) = VlanPacket::new(payload) {
            vlan      = Some(pkt.get_vlan_identifier());
            ethertype = pkt.get_ethertype();
            payload   = &payload[pkt.packet_size()..];
        } else {
            return (None, None)
        }
    }

    match ethertype {
        EtherTypes::Ipv4 => (vlan, Ipv4Packet::new(payload).map(Packet::IPv4)),
        EtherTypes::Ipv6 => (vlan, Ipv6Packet::new(payload).map(Packet::IPv6)),
        _                => (vlan, Opaque::new(ethertype.0, payload).map(Packet::Other)),
    }
}

pub fn decode_from_l3<'a>(buf: &'a [u8]) -> Option<Packet<'a>> {
    if buf.len() < 1 {
        return None
    }

    match buf[0] >> 4 {
        4 => Ipv4Packet::new(buf).map(Packet::IPv4),
        6 => Ipv6Packet::new(buf).map(Packet::IPv6),
        _ => None,
    }
}

impl<'a> Packet<'a> {
    pub fn src(&self) -> IpAddr {
        match *self {
            Packet::IPv4(ref p) => IpAddr::V4(p.get_source()),
            Packet::IPv6(ref p) => IpAddr::V6(p.get_source()),
            Packet::Other(..)   => IpAddr::V4(Ipv4Addr::from(0)),
        }
    }

    pub fn dst(&self) -> IpAddr {
        match *self {
            Packet::IPv4(ref p) => IpAddr::V4(p.get_destination()),
            Packet::IPv6(ref p) => IpAddr::V6(p.get_destination()),
            Packet::Other(..)   => IpAddr::V4(Ipv4Addr::from(0)),
        }
    }

    pub fn tos(&self) -> u8 {
        match *self {
            Packet::IPv4(ref p) => p.get_dscp() << 2 | p.get_ecn(),
            Packet::IPv6(ref p) => p.get_traffic_class(),
            Packet::Other(..)   => 0,
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            Packet::IPv4(ref p)  => p.packet().len(),
            Packet::IPv6(ref p)  => p.packet().len(),
            Packet::Other(ref o) => o.payload.len(),
        }
    }

    pub fn payload(&self) -> &[u8] {
        match *self {
            Packet::IPv4(ref p)  => p.payload(),
            Packet::IPv6(ref p)  => p.payload(),
            Packet::Other(ref o) => o.payload,
        }
    }

    pub fn transport<'n>(&self, p: &'n [u8]) -> Option<Transport<'n>> {
        match *self {
            Packet::IPv4(ref ip) => self.next(ip.get_next_level_protocol(), ip.payload_slice(p)),
            Packet::IPv6(ref ip) => self.next(ip.get_next_header(),         ip.payload_slice(p)),
            Packet::Other(..)    => None,
        }
    }

    fn next<'n>(&self, next: IpNextHeaderProtocol, payload: &'n [u8]) -> Option<Transport<'n>> {
        match next {
            IpNextHeaderProtocols::Icmp => IcmpPacket::new(payload).map(Transport::ICMP),
            IpNextHeaderProtocols::Tcp  => TcpPacket::new(payload).map(Transport::TCP),
            IpNextHeaderProtocols::Udp  => UdpPacket::new(payload).map(Transport::UDP),
            _                           => Opaque::new(next.0, payload).map(Transport::Other)
        }
    }
}

impl<'a> Opaque<'a> {
    fn new<T: Into<u16>>(protocol: T, payload: &'a [u8]) -> Option<Opaque<'a>> {
        Some(Opaque {
            protocol: protocol.into(),
            payload:  payload,
        })
    }
}

trait PayloadSlice {
    fn payload_slice<'p>(&self, p: &'p [u8]) -> &'p [u8];
}

impl<'p> PayloadSlice for Ipv4Packet<'p> {
    fn payload_slice<'b>(&self, p: &'b [u8]) -> &'b [u8] {
        let n = self.get_header_length() * 4;
        let m = (self.get_total_length() as usize).saturating_sub(n as usize);
        &p[..min(p.len(), m)]
    }
}

impl<'p> PayloadSlice for Ipv6Packet<'p> {
    fn payload_slice<'b>(&self, p: &'b [u8]) -> &'b [u8] {
        let n = self.get_payload_length() as usize;
        &p[..min(p.len(), n)]
    }
}
