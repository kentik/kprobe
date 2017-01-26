use std::net::IpAddr;

use pnet::packet::{Packet as PacketExt};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

#[derive(Debug)]
pub enum Packet<'a> {
    IPv4(Ipv4Packet<'a>),
    IPv6(Ipv6Packet<'a>),
}

#[derive(Debug)]
pub enum Transport<'a> {
    TCP(TcpPacket<'a>),
    UDP(UdpPacket<'a>),
}

pub fn decode<'a>(p: &'a EthernetPacket<'a>) -> Option<Packet<'a>> {
    match p.get_ethertype() {
        EtherTypes::Ipv4 => Ipv4Packet::new(p.payload()).map(|p| Packet::IPv4(p)),
        EtherTypes::Ipv6 => Ipv6Packet::new(p.payload()).map(|p| Packet::IPv6(p)),
        _                => None,
    }
}

impl<'a> Packet<'a> {
    pub fn transport(&self) -> Option<Transport> {
        match *self {
            Packet::IPv4(ref p) => self.next(p.get_next_level_protocol(), p.payload()),
            Packet::IPv6(ref p) => self.next(p.get_next_header(),         p.payload()),
        }
    }

    pub fn src(&self) -> IpAddr {
        match *self {
            Packet::IPv4(ref p) => IpAddr::V4(p.get_source()),
            Packet::IPv6(ref p) => IpAddr::V6(p.get_source()),
        }
    }

    pub fn dst(&self) -> IpAddr {
        match *self {
            Packet::IPv4(ref p) => IpAddr::V4(p.get_destination()),
            Packet::IPv6(ref p) => IpAddr::V6(p.get_destination()),
        }
    }

    fn next<'n>(&self, next: IpNextHeaderProtocol, payload: &'n [u8]) -> Option<Transport<'n>> {
        match next {
            IpNextHeaderProtocols::Tcp => TcpPacket::new(payload).map(|t| Transport::TCP(t)),
            IpNextHeaderProtocols::Udp => UdpPacket::new(payload).map(|t| Transport::UDP(t)),
            _                          => None,
        }
    }
}
