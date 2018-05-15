mod ipv4;
mod none;

use std::borrow::Cow;
use time::Duration;
use crate::flow::Timestamp;
use crate::packet::Packet;
use Packet::*;

#[derive(Debug)]
pub struct Output<'p> {
    pub packets: u16,
    pub frags:   u16,
    pub bytes:   usize,
    pub data:    Cow<'p, [u8]>,
}

pub struct Reassembler {
    active:  bool,
    ipv4:    ipv4::Reassembler,
    none:    none::Reassembler,
    flushed: Timestamp,
    timeout: Duration,
}

impl Reassembler {
    pub fn new(active: bool) -> Self {
        Reassembler {
            active:  active,
            ipv4:    ipv4::Reassembler::new(),
            none:    none::Reassembler::new(),
            flushed: Timestamp::zero(),
            timeout: Duration::seconds(60),
        }
    }

    pub fn reassemble<'p>(&mut self, ts: Timestamp, p: &'p Packet<'p>) -> Option<Output<'p>> {
        match *p {
            IPv4(ref p) if self.active => self.ipv4.reassemble(ts, p),
            _                          => self.none.reassemble(p),
        }
    }

    pub fn flush(&mut self, ts: Timestamp) {
        if (ts - self.flushed).num_seconds() > 15 {
            self.ipv4.clear(ts, self.timeout);
            self.flushed = ts;
        }
    }
}
