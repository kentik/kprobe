use libkflow::kflowCustom;
use protocol::Decoders;
use queue::FlowQueue;
use sample::Sampler;

pub struct Config {
    pub customs: Vec<kflowCustom>,
    pub decode:  bool,
    pub sample:  Option<u64>,
}

impl Config {
    pub fn queue(&self) -> FlowQueue {
        FlowQueue::new(self.sample, &self.customs, match self.decode {
            true  => Decoders::new(&self.customs),
            false => Decoders::new(&[]),
        })
    }

    pub fn sampler(&self) -> Option<Sampler> {
        self.sample.map(Sampler::new)
    }
}
