use std::collections::HashMap;
use time::Duration;
use flow::{Flow, Key, Timestamp, Transport};
use custom::Customs;
use libkflow::kflowCustom;

const KFLOW_APPL_LATENCY_MS:      &str = "APPL_LATENCY_MS";
const KFLOW_CLIENT_NW_LATENCY_MS: &str = "CLIENT_NW_LATENCY_MS";
const KFLOW_SERVER_NW_LATENCY_MS: &str = "SERVER_NW_LATENCY_MS";

pub struct Tracker {
    cli_latency: Option<u64>,
    srv_latency: Option<u64>,
    app_latency: Option<u64>,
    states:      HashMap<Key, State>,
}

pub struct State {
    latency: Option<Duration>,
    rtt:     Option<RTT>,
    syn:     Option<Timestamp>,
    payload: Option<Timestamp>,
    last:    Timestamp,
}

#[derive(Debug, Copy, Clone)]
pub enum RTT {
    Server(Duration),
    Client(Duration),
}

impl Tracker {
    pub fn new(cs: &[kflowCustom]) -> Self {
        let cs = cs.iter().map(|c| {
            (c.name(), c.id)
        }).collect::<HashMap<_, _>>();

        Tracker{
            cli_latency: cs.get(KFLOW_CLIENT_NW_LATENCY_MS).cloned(),
            srv_latency: cs.get(KFLOW_SERVER_NW_LATENCY_MS).cloned(),
            app_latency: cs.get(KFLOW_APPL_LATENCY_MS).cloned(),
            states:      HashMap::new(),
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

        if let Transport::TCP{ flags } = flow.transport {
            const SYN: u16 = 0b00010;
            const ACK: u16 = 0b10000;

            let syn = flags & SYN == SYN;
            let ack = flags & ACK == ACK;

            if syn {
                this.syn = Some(flow.timestamp);
            }

            if syn && ack && this.rtt.is_none() {
                if let Some(&mut State{syn: Some(syn), ..}) = self.peer(flow) {
                    this.rtt = Some(RTT::Server(flow.timestamp - syn));
                }
            } else if ack && this.rtt.is_none() {
                if let Some(&mut State{syn: Some(syn), ..}) = self.peer(flow) {
                    this.rtt = Some(RTT::Client(flow.timestamp - syn));
                }
            }
        }

        this.last = flow.timestamp;
    }

    pub fn get(&self, key: &Key, cs: &mut Customs) {
        if let Some(ref this) = self.states.get(key) {
            if let Some(RTT::Client(d)) = this.rtt {
                let ms = d.num_milliseconds() / 2;
                self.cli_latency.map(|id| cs.add_u32(id, ms as u32));
            }

            if let Some(RTT::Server(d)) = this.rtt {
                let ms = d.num_milliseconds() / 2;
                self.srv_latency.map(|id| cs.add_u32(id, ms as u32));
            }

            if let Some(d) = this.latency {
                let ms = d.num_milliseconds();
                self.app_latency.map(|id| cs.add_u32(id, ms as u32));
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
                rtt:     None,
                syn:     None,
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
