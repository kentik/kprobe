use rand::distributions::{IndependentSample, Range};
use rand::StdRng;
use flow::Flow;

#[derive(Debug)]
pub enum Accept {
    Export,
    Decode,
    Ignore,
}

pub struct Sampler {
    r: Range<u64>,
    g: StdRng,
}

impl Sampler {
    pub fn new(n: u64) -> Self {
        Sampler{
            r: Range::new(0, n),
            g: StdRng::new().unwrap(),
        }
    }

    pub fn accept(&mut self, _flow: &Flow) -> Accept {
        match self.r.ind_sample(&mut self.g) {
            0 => Accept::Export,
            _ => Accept::Ignore,
        }
    }
}
