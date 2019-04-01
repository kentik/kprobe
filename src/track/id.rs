use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use crate::flow::{Direction, Flow};

pub struct Generator(RandomState);

impl Generator {
    pub fn new() -> Self {
        Generator(RandomState::new())
    }

    pub fn id(&self, flow: &Flow) -> u32 {
        let mut s = self.0.build_hasher();

        flow.protocol.hash(&mut s);
        if let Direction::Out = flow.direction {
            flow.ethernet.src.hash(&mut s);
            flow.src.hash(&mut s);
            flow.ethernet.dst.hash(&mut s);
            flow.dst.hash(&mut s);
        } else {
            flow.ethernet.dst.hash(&mut s);
            flow.dst.hash(&mut s);
            flow.ethernet.src.hash(&mut s);
            flow.src.hash(&mut s);
        }
        flow.ethernet.vlan.hash(&mut s);

        s.finish() as u32
    }
}
