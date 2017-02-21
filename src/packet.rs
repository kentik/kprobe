use std::net::IpAddr;

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
}

#[derive(Debug)]
pub enum Transport<'a> {
    ICMP(IcmpPacket<'a>),
    TCP(TcpPacket<'a>),
    UDP(UdpPacket<'a>),
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
        _                => (vlan, None),
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

    pub fn tos(&self) -> u8 {
        match *self {
            Packet::IPv4(ref p) => p.get_dscp() << 2 | p.get_ecn(),
            Packet::IPv6(ref p) => p.get_traffic_class(),
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            Packet::IPv4(ref p) => p.packet().len(),
            Packet::IPv6(ref p) => p.packet().len(),
        }
    }

    fn next<'n>(&self, next: IpNextHeaderProtocol, payload: &'n [u8]) -> Option<Transport<'n>> {
        match next {
            IpNextHeaderProtocols::Icmp => IcmpPacket::new(payload).map(Transport::ICMP),
            IpNextHeaderProtocols::Tcp  => TcpPacket::new(payload).map(Transport::TCP),
            IpNextHeaderProtocols::Udp  => UdpPacket::new(payload).map(Transport::UDP),
            _                           => None,
        }
    }
}
