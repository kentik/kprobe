#![allow(dead_code, unused_variables)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::u16;
use pnet::packet::{Packet as PacketExt};
use pnet::packet::ipv4::Ipv4Packet;
use time::Duration;
use flow::Timestamp;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct Key(Ipv4Addr, Ipv4Addr, u16, u8);

#[derive(Debug)]
pub struct Reassembler {
    buffers: HashMap<Key, Buffer>
}

#[derive(Debug)]
pub struct Buffer {
    data:  Vec<u8>,
    holes: Vec<Hole>,
    frags: usize,
    len:   usize,
    last:  Timestamp,
}

#[derive(Debug)]
struct Hole {
    first: u16,
    last:  u16,
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler{
            buffers: HashMap::new(),
        }
    }

    pub fn reassemble<'p>(&mut self, ts: Timestamp, p: &'p Ipv4Packet<'p>) -> Option<(usize, Cow<'p, [u8]>)> {
        let more   = p.get_flags() & 0b001 != 0;
        let offset = p.get_fragment_offset();

        if !more && offset == 0 {
            return Some((0, Cow::from(p.payload())));
        }

        let src   = p.get_source();
        let dst   = p.get_destination();
        let id    = p.get_identification();
        let proto = p.get_next_level_protocol().0;
        let key   = Key(src, dst, id, proto);

        let done = {
            let buf = self.buffers.entry(key).or_insert_with(Buffer::new);
            buf.fill(p, more);
            buf.last = ts;
            buf.holes.is_empty()
        };

        if done {
            self.buffers.remove(&key).map(|Buffer{ mut data, frags, len, .. }| {
                data.truncate(len);
                (frags, Cow::from(data))
            })
        } else {
            None
        }
    }

    pub fn clear(&mut self, ts: Timestamp, timeout: Duration) {
        self.buffers.retain(|_, b| !b.is_old(ts, timeout))
    }
}

impl Buffer {
    pub fn new() -> Self {
        let data  = vec![0; 65535];
        let holes = vec![Hole::empty()];
        Buffer{
            data:  data,
            holes: holes,
            frags: 0,
            len:   0,
            last:  Timestamp::zero(),
        }
    }

    fn fill<'p>(&mut self, p: &Ipv4Packet<'p>, more: bool) {
        let payload    = p.payload();
        let frag_first = p.get_fragment_offset() * 8;
        let frag_last  = frag_first.saturating_add(payload.len() as u16) - 1;

        for i in 0..self.holes.len() {
            let Hole{first: hole_first, last: hole_last} = self.holes[i];

            if frag_first > hole_last || frag_last < hole_first {
                continue
            }

            match self.holes.len() > 1 {
                true  => self.holes.swap_remove(i),
                false => self.holes.remove(i),
            };

            if frag_first > hole_first {
                let first = hole_first;
                let last  = frag_first - 1;
                self.holes.push(Hole::new(first, last));
            }

            if frag_last < hole_last && more {
                let first = frag_last + 1;
                let last  = hole_last;
                self.holes.push(Hole::new(first, last));
            }

            let n = frag_first as usize;
            let m = frag_last as usize + 1;
            self.data[n..m].copy_from_slice(payload);

            self.frags += 1;
            self.len   += payload.len();

            break;
        }
    }

    fn is_old(&self, ts: Timestamp, timeout: Duration) -> bool {
        (ts - self.last) > timeout
    }
}

impl Hole {
    fn new(first: u16, last: u16) -> Self {
        Hole{
            first: first,
            last:  last,
        }
    }

    fn empty() -> Self {
        Hole{
            first: 0,
            last:  u16::MAX,
        }
    }
}
