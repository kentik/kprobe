use std::borrow::Cow;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use packet::Packet;
use super::Output;

pub struct Reassembler {
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler {
        }
    }

    pub fn reassemble<'p>(&mut self, p: &'p Packet<'p>) -> Option<Output<'p>> {
        let data  = Cow::from(p.payload());
        let frags = match *p {
            Packet::IPv4(ref ip) => self.ipv4(ip),
            Packet::IPv6(ref ip) => self.ipv6(ip),
            Packet::Other(..)    => 0,
        };

        Some(Output {
            packets: 1,
            frags:   frags,
            bytes:   p.len(),
            data:    data,
        })
    }

    fn ipv4<'p>(&mut self, p: &'p Ipv4Packet<'p>) -> u16 {
        match p.get_flags() & 0b001 {
            0b001 => 1,
            _     => 0,
        }
    }

    fn ipv6<'p>(&mut self, p: &'p Ipv6Packet<'p>) -> u16 {
        // FIXME: check if IPv6 fragment
        let _ = p;
        0
    }

}
