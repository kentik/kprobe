use custom::Customs;
use libkflow::kflowCustom;
use queue::FlowQueue;
use sample::Sampler;

pub struct Config {
    pub customs: Vec<kflowCustom>,
    pub decode:  bool,
    pub sample:  Option<u64>,
}

impl Config {
    pub fn queue(&self) -> FlowQueue {
        let customs = Customs::new(&self.customs);
        FlowQueue::new(self.sample, customs, self.decode)
    }

    pub fn sampler(&self) -> Option<Sampler> {
        self.sample.map(Sampler::new)
    }
}
