use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use flow::{Addr, Flow, Protocol};
use flow::Protocol::*;

#[derive(Debug)]
pub enum Accept {
    Export,
    Decode,
    Ignore,
}

pub struct Sampler {
    n: u64,
    s: RandomState,
}

impl Sampler {
    pub fn new(n: u64) -> Self {
        let s = RandomState::new();
        Sampler{n, s}
    }

    pub fn accept(&self, flow: &Flow) -> Accept {
        let this = (flow.protocol, flow.src, flow.dst);
        let peer = (flow.protocol, flow.dst, flow.src);

        if self.select(this) {
            Accept::Export
        } else if !bidirectional(flow) {
            Accept::Ignore
        } else if self.select(peer) {
            Accept::Decode
        } else {
            Accept::Ignore
        }
    }

    fn select(&self, key: (Protocol, Addr, Addr)) -> bool {
        let mut s = self.s.build_hasher();
        key.hash(&mut s);
        s.finish() % self.n == 0
    }
}

fn bidirectional(flow: &Flow) -> bool {
    flow.protocol == TCP || flow.protocol == UDP
}
