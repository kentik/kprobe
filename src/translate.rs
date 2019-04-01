use std::collections::HashMap;
use crate::flow::{Addr, Flow};

#[derive(Debug)]
pub struct Translate {
    map: HashMap<Addr, Addr>,
}

impl Translate {
    pub fn new(specs: Vec<(Addr, Addr)>) -> Self {
        let map = specs.into_iter().collect();
        Translate{ map }
    }

    pub fn translate(&self, flow: &mut Flow) {
        self.map.get(&flow.src).map(|addr| flow.src = *addr);
        self.map.get(&flow.dst).map(|addr| flow.dst = *addr);
    }
}
