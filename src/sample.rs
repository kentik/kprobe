use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use flow::Flow;

pub struct Sampler {
    n: u64,
    s: RandomState,
}

impl Sampler {
    pub fn new(n: u64) -> Self {
        let s = RandomState::new();
        Sampler{n, s}
    }

    pub fn accept(&self, flow: &Flow) -> bool {
        let mut s = self.s.build_hasher();
        flow.protocol.hash(&mut s);
        if flow.src < flow.dst {
            flow.src.hash(&mut s);
            flow.dst.hash(&mut s);
        } else {
            flow.dst.hash(&mut s);
            flow.src.hash(&mut s);
        }
        s.finish() % self.n == 0
    }
}
