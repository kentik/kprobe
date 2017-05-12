use std::collections::HashMap;
use std::time::SystemTime;
use flow::*;
use libkflow::{self, kflowCustom};
use protocol::{Customs, Decoder, Decoders};

#[derive(Debug)]
pub struct Counter {
    pub ethernet:  Ethernet,
    pub direction: Direction,
    pub tos:       u8,
    pub tcp_flags: u16,
    pub packets:   u64,
    pub bytes:     u64,
    pub decoder:   Decoder,
}

pub struct FlowQueue {
    flows:    HashMap<Key, Counter>,
    customs:  Customs,
    decoders: Decoders,
    flushed:  SystemTime,
}

impl FlowQueue {
    pub fn new(customs: Vec<kflowCustom>) -> FlowQueue {
        FlowQueue {
            flows:    HashMap::new(),
            customs:  Customs::new(customs.len()),
            decoders: Decoders::new(customs),
            flushed:  SystemTime::now(),
        }
    }

    pub fn add(&mut self, dir: Direction, flow: Flow) {
        let key = Key(flow.protocol, flow.src, flow.dst);
        let dec = self.record(key, dir, &flow);

        self.customs.clear();

        if self.decoders.decode(dec, &flow, &mut self.customs) {
            self.flows.remove(&key).map(|ctr| {
                let cs = Some(&self.customs[..]);
                libkflow::send(&key, &ctr, cs).expect("failed to send flow");
            });
        }
    }

    fn record(&mut self, key: Key, dir: Direction, flow: &Flow) -> Decoder {
        let decoders = &mut self.decoders;
        let ctr = self.flows.entry(key).or_insert_with(|| {
            Counter {
                ethernet:  flow.ethernet,
                direction: dir,
                tos:       0,
                tcp_flags: 0,
                packets:   0,
                bytes:     0,
                decoder:   decoders.classify(flow),
            }
        });

        ctr.tos     |= flow.tos;
        ctr.packets += 1;
        ctr.bytes   += flow.bytes as u64;

        if let Transport::TCP { flags } = flow.transport {
            ctr.tcp_flags |= flags;
        }

        ctr.decoder
    }

    pub fn flush(&mut self) {
        if let Ok(time) = self.flushed.elapsed() {
            // FIXME: proper flush interval
            if time.as_secs() < 15 {
                return;
            }
        }

        for (key, ctr) in &self.flows {
            // let src = format!("{}:{}", key.1.addr, key.1.port);
            // let dst = format!("{}:{}", key.2.addr, key.2.port);

            // println!("{:?} {}->{} PACKETS {} BYTES {}", key.0, src, dst, ctr.packets, ctr.bytes);

            libkflow::send(key, ctr, None).expect("failed to send flow");
        }

        self.flows.clear();
        self.flushed = SystemTime::now();

        while let Some(msg) = libkflow::error() {
            println!("libkflow error: {}", msg);
        }
    }
}
