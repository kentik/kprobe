use std::collections::HashMap;
use time::Duration;
use flow::*;
use custom::Customs;
use libkflow;
use protocol::{Classify, Decoder, Decoders};
use timer::{Timeout, Timer};
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
    pub decoder:   Decoder,
    pub export:    Timestamp,
}

pub struct FlowQueue {
    flows:    HashMap<Key, Counter>,
    decoders: Decoders,
    tracker:  Tracker,
    classify: Classify,
    customs:  Customs,
    sample:   u32,
    compact:  Timer,
    export:   Timer,
    timeout:  Timeout,
}

impl FlowQueue {
    pub fn new(sample: Option<u64>, customs: Customs, mut classify: Classify, decode: bool) -> FlowQueue {
        FlowQueue {
            flows:    HashMap::new(),
            decoders: Decoders::new(&customs, &mut classify, decode),
            tracker:  Tracker::new(&customs),
            classify: classify,
            customs:  customs,
            sample:   sample.unwrap_or(1) as u32,
            compact:  Timer::new(Duration::seconds(30)),
            export:   Timer::new(Duration::seconds(2)),
            timeout:  Timeout::new(Duration::seconds(15)),
        }
    }

    pub fn add(&mut self, flow: Flow) {
        let key = Key(flow.protocol, flow.src, flow.dst);
        let dec = self.record(key, &flow);

        if self.decoders.decode(dec, &flow, &mut self.customs) {
            if flow.export {
                if let Some(ctr) = self.flows.get_mut(&key) {
                    let customs = &mut self.customs;
                    let tracker = &mut self.tracker;
                    Self::send(customs, tracker, &key, ctr, self.sample);
                }
            }
            self.customs.clear();
        }
    }

    fn record(&mut self, key: Key, flow: &Flow) -> Decoder {
        let classify = &mut self.classify;
        let timeout  = &mut self.timeout;

        self.tracker.add(flow);

        let ctr = self.flows.entry(key).or_insert_with(|| {
            let export = timeout.first(flow.timestamp);
            Counter {
                ethernet:  flow.ethernet,
                direction: flow.direction,
                tos:       0,
                tcp_flags: 0,
                packets:   0,
                bytes:     0,
                fragments: 0,
                decoder:   classify.find(flow),
                export:    export,
            }
        });

        if flow.export {
            ctr.tos       |= flow.tos;
            ctr.packets   += flow.packets as u64;
            ctr.bytes     += flow.bytes as u64;
            ctr.fragments += flow.fragments as u64;

            if let Transport::TCP { flags, .. } = flow.transport {
                ctr.tcp_flags |= flags;
            }
        }

        ctr.decoder
    }

    pub fn export(&mut self, ts: Timestamp) {
        if !self.export.ready(ts) {
            return;
        }

        let customs  = &mut self.customs;
        let decoders = &mut self.decoders;
        let tracker  = &mut self.tracker;

        for (key, ctr) in &mut self.flows {
            if ctr.export <= ts && ctr.packets > 0 {
                decoders.append(ctr.decoder, key, customs);
                Self::send(customs, tracker, key, ctr, self.sample);
                ctr.export = self.timeout.next(ctr.export);
                customs.clear();
            }
        }

        if self.compact.ready(ts) {
            self.flows.retain(|_, c| c.export > ts);
            decoders.clear(ts);
            tracker.clear(ts);
        }

        while let Some(msg) = libkflow::error() {
            println!("libkflow error: {}", msg);
        }
    }

    fn send(customs: &mut Customs, tracker: &mut Tracker, key: &Key, ctr: &mut Counter, sr: u32) {
        customs.append(ctr);
        tracker.append(key, ctr.direction, customs);
        libkflow::send(key, ctr, sr, match &customs {
            cs if !cs.is_empty() => Some(cs),
            _                    => None,
        }).expect("failed to send flow");
        ctr.clear();
    }
}

impl Counter {
    fn clear(&mut self) {
        self.tos       = 0;
        self.tcp_flags = 0;
        self.packets   = 0;
        self.bytes     = 0;
        self.fragments = 0;
    }
}

#[cfg(test)]
impl FlowQueue {
    pub fn customs(&mut self) -> &mut Customs {
        &mut self.customs
    }
}

#[cfg(test)]
impl ::std::ops::Deref for FlowQueue {
    type Target = HashMap<Key, Counter>;
    fn deref(&self) -> &Self::Target {
        &self.flows
    }
}
