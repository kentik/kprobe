use std::collections::HashMap;
use flow::*;
use custom::Customs;
use libkflow::{self, kflowCustom};
use protocol::{Decoder, Decoders};
use track::Tracker;

#[derive(Debug)]
pub struct Counter {
    pub ethernet:  Ethernet,
    pub direction: Direction,
    pub tos:       u8,
    pub tcp_flags: u16,
    pub packets:   u64,
    pub bytes:     u64,
    pub fragments: u64,
    pub export:    bool,
    pub decoder:   Decoder,
}

pub struct FlowQueue {
    flows:    HashMap<Key, Counter>,
    customs:  Customs,
    decoders: Decoders,
    tracker:  Tracker,
    sample:   u32,
    flushed:  Timestamp,
}

impl FlowQueue {
    pub fn new(sample: Option<u64>, customs: Vec<kflowCustom>) -> FlowQueue {
        FlowQueue {
            flows:    HashMap::new(),
            customs:  Customs::new(&customs),
            decoders: Decoders::new(&customs),
            tracker:  Tracker::new(&customs),
            sample:   sample.unwrap_or(1) as u32,
            flushed:  Timestamp::zero(),
        }
    }

    pub fn add(&mut self, dir: Direction, flow: Flow) {
        let key = Key(flow.protocol, flow.src, flow.dst);
        let dec = self.record(key, dir, &flow);

        if self.decoders.decode(dec, &flow, &mut self.customs) {
            if flow.export {
                self.flows.remove(&key).map(|ctr| {
                    let customs = &mut self.customs;
                    let tracker = &mut self.tracker;
                    Self::send(customs, tracker, &key, &ctr, self.sample)
                });
            }
            self.customs.clear();
        }
    }

    fn record(&mut self, key: Key, dir: Direction, flow: &Flow) -> Decoder {
        let decoders = &mut self.decoders;

        self.tracker.add(flow);

        let ctr = self.flows.entry(key).or_insert_with(|| {
            Counter {
                ethernet:  flow.ethernet,
                direction: dir,
                tos:       0,
                tcp_flags: 0,
                packets:   0,
                bytes:     0,
                fragments: 0,
                export:    flow.export,
                decoder:   decoders.classify(flow),
            }
        });

        ctr.tos       |= flow.tos;
        ctr.packets   += flow.packets as u64;
        ctr.bytes     += flow.bytes as u64;
        ctr.fragments += flow.fragments as u64;

        if let Transport::TCP { flags, .. } = flow.transport {
            ctr.tcp_flags |= flags;
        }

        ctr.decoder
    }

    pub fn flush(&mut self, ts: Timestamp) {
        // FIXME: proper flush interval
        if (ts - self.flushed).num_seconds() < 15 {
            return;
        }

        let customs  = &mut self.customs;
        let decoders = &mut self.decoders;
        let tracker  = &mut self.tracker;

        for (key, ctr) in self.flows.drain().filter(|e| e.1.export) {
            decoders.append(ctr.decoder, &key, customs);
            Self::send(customs, tracker, &key, &ctr, self.sample);
            customs.clear();
        }

        decoders.clear(ts);
        tracker.clear(ts);
        self.flushed = ts;

        while let Some(msg) = libkflow::error() {
            println!("libkflow error: {}", msg);
        }
    }

    fn send(customs: &mut Customs, tracker: &mut Tracker, key: &Key, ctr: &Counter, sr: u32) {
        customs.append(ctr);
        tracker.append(key, ctr.direction, customs);
        libkflow::send(key, ctr, sr, match &customs[..] {
            cs if !cs.is_empty() => Some(cs),
            _                    => None,
        }).expect("failed to send flow");
    }
}
