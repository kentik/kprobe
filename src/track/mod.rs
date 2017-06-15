use std::collections::HashMap;
use time::Duration;
use flow::{Flow, Key, Timestamp};
use custom::Customs;
use libkflow::kflowCustom;

const KFLOW_APPL_LATENCY_MS: &str = "APPL_LATENCY_MS";

pub struct Tracker {
    latency: Option<u64>,
    states:  HashMap<Key, State>,
}

pub struct State {
    latency: Option<Duration>,
    payload: Option<Timestamp>,
    last:    Timestamp,
}

impl Tracker {
    pub fn new(cs: &[kflowCustom]) -> Self {
        let cs = cs.iter().map(|c| {
            (c.name(), c.id)
        }).collect::<HashMap<_, _>>();

        Tracker{
            latency: cs.get(KFLOW_APPL_LATENCY_MS).cloned(),
            states:  HashMap::new(),
        }
    }

    pub fn add(&mut self, flow: &Flow) {
        let this = self.this(&flow);

        if this.payload.is_none() && flow.payload.len() > 0 {
            this.payload = Some(flow.timestamp);

            if let Some(peer @ &mut State{latency: None, ..}) = self.peer(&flow) {
                peer.latency = peer.payload.map(|ts| flow.timestamp - ts);
                //let key = Key(flow.protocol, flow.dst, flow.src);
                //println!("{:?} latency {:?}", key, peer.latency);
            }
        }

        this.last = flow.timestamp;
    }

    pub fn get(&self, key: &Key, cs: &mut Customs) {
        if let Some(ref this) = self.states.get(key) {
            if let Some(d) = this.latency {
                self.latency.map(|id| cs.add_u32(id, d.num_milliseconds() as u32));
            }
        }
    }

    pub fn clear(&mut self, ts: Timestamp) {
        let timeout = Duration::seconds(60);
        self.states.retain(|_, s| (ts - s.last) > timeout)
    }

    pub fn latency(&self, key: &Key) -> Option<Duration> {
        self.states.get(key).and_then(|s| s.latency)
    }

    fn this<'a>(&mut self, flow: &Flow) -> &'a mut State {
        let key = Key(flow.protocol, flow.src, flow.dst);
        let mut s = self.states.entry(key).or_insert_with(|| {
            State{
                latency: None,
                payload: None,
                last:    flow.timestamp,
            }
        });
        unsafe { &mut *(s as *mut State) }
    }

    fn peer<'a>(&mut self, flow: &Flow) -> Option<&'a mut State> {
        let key = Key(flow.protocol, flow.dst, flow.src);
        self.states.get_mut(&key).map(|s| unsafe {
            &mut *(s as *mut State)
        })
    }
}
