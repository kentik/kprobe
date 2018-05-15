use std::mem;
use crate::custom::Customs;
use crate::flow::Addr;
use crate::libkflow::kflowCustom;
use crate::protocol::Classify;
use crate::queue::FlowQueue;
use crate::sample::{Sample, Sampler};
use crate::reasm::Reassembler;
use crate::translate::Translate;

pub struct Config {
    pub classify:  Classify,
    pub customs:   Vec<kflowCustom>,
    pub decode:    bool,
    pub sample:    Sample,
    pub translate: Option<Vec<(Addr, Addr)>>,
}

impl Config {
    pub fn queue(self) -> FlowQueue {
        let customs = Customs::new(&self.customs);
        FlowQueue::new(self.sample, customs, self.classify, self.decode)
    }

    pub fn reassembler(&self) -> Reassembler {
        match self.sample {
            Sample::External(..) => Reassembler::new(false),
            _                    => Reassembler::new(true),
        }
    }

    pub fn sampler(&self) -> Option<Sampler> {
        match self.sample {
            Sample::Internal(n) => Some(Sampler::new(n)),
            _                   => None,
        }
    }

    pub fn translate(&mut self) -> Option<Translate> {
        mem::replace(&mut self.translate, None).map(Translate::new)
    }
}
