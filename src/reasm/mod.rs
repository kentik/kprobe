mod ipv4;

use std::borrow::Cow;
use time::Duration;
use crate::time::Timestamp;
use crate::packet::Packet;

#[derive(Debug)]
pub struct Output<'p> {
    pub packets: u16,
    pub frags:   u16,
    pub bytes:   usize,
    pub data:    Cow<'p, [u8]>,
}

impl<'p> Output<'p> {
    fn single(p: &'p Packet<'p>) -> Self {
        let data = Cow::from(p.payload());
        Self {
            packets: 1,
            frags:   0,
            bytes:   p.len(),
            data:    data,
        }
    }
}

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

    pub fn reassemble<'p>(&mut self, ts: Timestamp, p: &'p Packet<'p>) -> Option<Output<'p>> {
        match *p {
            Packet::IPv4(ref p) => self.ipv4.reassemble(ts, p),
            _                   => Some(Output::single(p)),
        }
    }

    pub fn flush(&mut self, ts: Timestamp) {
        if (ts - self.flushed).whole_seconds() > 15 {
            self.ipv4.clear(ts, self.timeout);
            self.flushed = ts;
        }
    }
}
