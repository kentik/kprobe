mod ipv4;

use std::borrow::Cow;
use pnet::packet::{Packet as PacketExt};
use time::Duration;
use flow::Timestamp;
use packet::Packet;

pub struct Reassembler {
    ipv4:    ipv4::Reassembler,
    flushed: Timestamp,
    timeout: Duration,
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler{
            ipv4:    ipv4::Reassembler::new(),
            flushed: Timestamp::zero(),
            timeout: Duration::seconds(60),
        }
    }

    pub fn reassemble<'p>(&mut self, ts: Timestamp, p: &'p Packet<'p>) -> Option<(usize, Cow<'p, [u8]>)> {
        match *p {
            Packet::IPv4(ref p) => self.ipv4.reassemble(ts, p),
            Packet::IPv6(ref p) => Some((0, Cow::from(p.payload()))),
            Packet::Other(..)   => None,
        }
    }

    pub fn flush(&mut self, ts: Timestamp) {
        if (ts - self.flushed).num_seconds() > 15 {
            self.ipv4.clear(ts, self.timeout);
            self.flushed = ts;
        }
    }
}
