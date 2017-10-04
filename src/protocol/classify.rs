use std::cmp::max;
use std::cmp::Ordering::*;
use flow::{Flow, Protocol};
use flow::Protocol::{TCP, UDP};
use super::Decoder;

#[derive(Debug)]
pub struct Classify {
    pub tcp: Vec<Decoder>,
    pub udp: Vec<Decoder>,
}

impl Classify {
    pub fn new() -> Self {
        Classify{
            tcp: vec![Decoder::None; 512],
            udp: vec![Decoder::None; 512],
        }
    }

    pub fn add(&mut self, p: Protocol, port: u16, d: Decoder) {
        match p {
            TCP => Self::insert(&mut self.tcp, port, d),
            UDP => Self::insert(&mut self.udp, port, d),
            _   => panic!("{:?} not supported", p),
        }
    }

    pub fn find(&self, flow: &Flow) -> Decoder {
        match flow.protocol {
            TCP => Self::search(&self.tcp, flow.src.port, flow.dst.port),
            UDP => Self::search(&self.udp, flow.src.port, flow.dst.port),
            _   => Decoder::None,
        }
    }

    fn search(vec: &Vec<Decoder>, src: u16, dst: u16) -> Decoder {
        let (x, y) = match src.cmp(&dst) {
            Less | Equal => (src as usize, dst as usize),
            Greater      => (dst as usize, src as usize),
        };

        match vec.get(x) {
            None | Some(&Decoder::None) => vec.get(y),
            decoder                     => decoder,
        }.map(|d| *d).unwrap_or(Decoder::None)
    }

    fn insert(vec: &mut Vec<Decoder>, port: u16, d: Decoder) {
        let port = port as usize;
        let last = max(port + 1, vec.len());
        vec.resize(last, Decoder::None);
        vec[port] = d;
    }
}
