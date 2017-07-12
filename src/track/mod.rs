use std::collections::HashMap;
use time::Duration;
use flow::{Direction, Flow, Key, Timestamp, Transport};
use custom::Customs;
use libkflow::kflowCustom;

const KFLOW_APPL_LATENCY_MS:        &str = "APPL_LATENCY_MS";
const KFLOW_CLIENT_NW_LATENCY_MS:   &str = "CLIENT_NW_LATENCY_MS";
const KFLOW_SERVER_NW_LATENCY_MS:   &str = "SERVER_NW_LATENCY_MS";
const KFLOW_RETRANSMITTED_PKTS_IN:  &str = "RETRANSMITTED_IN_PKTS";
const KFLOW_RETRANSMITTED_PKTS_OUT: &str = "RETRANSMITTED_OUT_PKTS";
const KFLOW_OOORDER_PKTS_IN:        &str = "OOORDER_IN_PKTS";
const KFLOW_OOORDER_PKTS_OUT:       &str = "OOORDER_OUT_PKTS";

pub struct Tracker {
    cli_latency:     Option<u64>,
    srv_latency:     Option<u64>,
    app_latency:     Option<u64>,
    retransmits_in:  Option<u64>,
    retransmits_out: Option<u64>,
    ooorder_in:      Option<u64>,
    ooorder_out:     Option<u64>,
    states:          HashMap<Key, State>,
}

pub struct State {
    latency:     Option<Duration>,
    rtt:         Option<RTT>,
    syn:         Option<Timestamp>,
    payload:     Option<Timestamp>,
    seq:         u32,
    retransmits: u64,
    ooorder:     u64,
    last:        Timestamp,
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
            cli_latency:     cs.get(KFLOW_CLIENT_NW_LATENCY_MS).cloned(),
            srv_latency:     cs.get(KFLOW_SERVER_NW_LATENCY_MS).cloned(),
            app_latency:     cs.get(KFLOW_APPL_LATENCY_MS).cloned(),
            retransmits_in:  cs.get(KFLOW_RETRANSMITTED_PKTS_IN).cloned(),
            retransmits_out: cs.get(KFLOW_RETRANSMITTED_PKTS_OUT).cloned(),
            ooorder_in:      cs.get(KFLOW_OOORDER_PKTS_IN).cloned(),
            ooorder_out:     cs.get(KFLOW_OOORDER_PKTS_OUT).cloned(),
            states:          HashMap::new(),
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

        if let Transport::TCP{ seq, flags } = flow.transport {
            const FIN: u16 = 0b00001;
            const SYN: u16 = 0b00010;
            const RST: u16 = 0b00100;
            const ACK: u16 = 0b10000;

            let fin = flags & FIN == FIN;
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

            let seglen    = flow.payload.len();
            let keepalive = seglen <= 1 && seq == this.seq.wrapping_sub(1) && flags & (SYN|FIN|RST) == 0;

            if (seglen > 0 || (fin || syn)) && seq != this.seq && !keepalive {
                let ooo = (flow.timestamp - this.last) < match this.rtt {
                    Some(RTT::Server(d)) => d,
                    Some(RTT::Client(d)) => d,
                    None                 => Duration::milliseconds(3),
                };

                if !ooo {
                    this.retransmits += 1;
                } else {
                    this.ooorder += 1;
                }
            }

            let nextseq = match seq + seglen as u32 {
                n if syn || fin => n + 1,
                n               => n,
            };

            if nextseq > this.seq {
                this.seq  = nextseq;
                this.last = flow.timestamp;
            }
        } else {
            this.last = flow.timestamp;
        }
    }

    pub fn get(&mut self, key: &Key, dir: Direction, cs: &mut Customs) {
        if let Some(ref mut this) = self.states.get_mut(key) {
            let (cli, srv) = match this.rtt {
                Some(RTT::Client(d)) => (d.num_milliseconds() / 2, 0),
                Some(RTT::Server(d)) => (0, d.num_milliseconds() / 2),
                None                 => (0, 0),
            };

            let app = this.latency.map(|d| d.num_milliseconds()).unwrap_or(0);

            self.cli_latency.map(|id| cs.add_u32(id, cli as u32));
            self.srv_latency.map(|id| cs.add_u32(id, srv as u32));
            self.app_latency.map(|id| cs.add_u32(id, app as u32));

            if this.retransmits > 0 {
                match dir {
                    Direction::In => &self.retransmits_in,
                    _             => &self.retransmits_out,
                }.map(|id| cs.add_u32(id, this.retransmits as u32));
                this.retransmits = 0;
            }

            if this.ooorder > 0 {
                match dir {
                    Direction::In => &self.ooorder_in,
                    _             => &self.ooorder_out,
                }.map(|id| cs.add_u32(id, this.ooorder as u32));
                this.ooorder = 0;
            }
        }
    }

    pub fn clear(&mut self, ts: Timestamp) {
        let timeout = Duration::seconds(60);
        self.states.retain(|_, s| (ts - s.last) < timeout)
    }

    pub fn latency(&self, key: &Key) -> Option<Duration> {
        self.states.get(key).and_then(|s| s.latency)
    }

    pub fn retransmits(&self, key: &Key) -> Option<u64> {
        self.states.get(key).map(|s| s.retransmits)
    }

    pub fn ooorder(&self, key: &Key) -> Option<u64> {
        self.states.get(key).map(|s| s.ooorder)
    }

    fn this<'a>(&mut self, flow: &Flow) -> &'a mut State {
        let key = Key(flow.protocol, flow.src, flow.dst);
        let mut s = self.states.entry(key).or_insert_with(|| {
            let seq = match flow.transport {
                Transport::TCP{ seq, .. } => seq,
                _                         => 0,
            };

            State{
                latency:     None,
                rtt:         None,
                syn:         None,
                payload:     None,
                seq:         seq,
                retransmits: 0,
                ooorder:     0,
                last:        flow.timestamp,
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
