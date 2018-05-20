use std::mem;
use custom::Customs;
use flow::Addr;
use libkflow::kflowCustom;
use protocol::Classify;
use queue::FlowQueue;
use sample::Sampler;
use translate::Translate;

pub struct Config {
    pub classify:  Classify,
    pub customs:   Vec<kflowCustom>,
    pub decode:    bool,
    pub sample:    Option<u64>,
    pub translate: Option<Vec<(Addr, Addr)>>,
}

impl Config {
    pub fn queue(self) -> FlowQueue {
        let customs = Customs::new(&self.customs);
        FlowQueue::new(self.sample, customs, self.classify, self.decode)
    }

    pub fn sampler(&self) -> Option<Sampler> {
        None
    }

    pub fn translate(&mut self) -> Option<Translate> {
        mem::replace(&mut self.translate, None).map(Translate::new)
    }
}
