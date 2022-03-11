pub mod id;

use std::collections::HashMap;
use time::Duration;
use crate::flow::{Flow, Key, Transport, Window};
use crate::flow::{FIN, SYN, RST, ACK};
use crate::custom::*;
use crate::time::Timestamp;
use crate::track::id::Generator;

pub struct Tracker {
    conn_id:      Option<u64>,
    cli_latency:  Option<u64>,
    srv_latency:  Option<u64>,
    fpx_latency:  Option<u64>,
    retx_out:     Option<u64>,
    retx_repeats: Option<u64>,
    ooorder_in:   Option<u64>,
    rwindow:      Option<u64>,
    zwindows:     Option<u64>,
    generator:    Generator,
    states:       HashMap<Key, State>,
}

#[derive(Debug)]
pub struct State {
    id:          u32,
    latency:     Option<Duration>,
    rtt:         Option<RTT>,
    syn:         Option<Timestamp>,
    payload:     Option<Timestamp>,
    fin:         Option<Timestamp>,
    seq:         u32,
    window:      Window,
    retransmits: Retransmits,
    ooorder:     u32,
    zwindows:    u32,
    last:        Timestamp,
}

#[derive(Debug)]
struct Retransmits {
    serial:  u32,
    total:   u32,
    repeats: u32,
    seq:     u32,
}

#[derive(Debug, Copy, Clone)]
pub enum RTT {
    Server(Duration),
    Client(Duration),
}

impl Tracker {
    pub fn new(cs: &Customs) -> Self {
        Tracker{
            conn_id:      cs.get(CONNECTION_ID).ok(),
            cli_latency:  cs.get(CLIENT_NW_LATENCY).ok(),
            srv_latency:  cs.get(SERVER_NW_LATENCY).ok(),
            fpx_latency:  cs.get(FPX_LATENCY).ok(),
            retx_out:     cs.get(RETRANSMITTED_OUT).ok(),
            retx_repeats: cs.get(REPEATED_RETRANSMITS).ok(),
            ooorder_in:   cs.get(OOORDER_IN).ok(),
            rwindow:      cs.get(RECEIVE_WINDOW).ok(),
            zwindows:     cs.get(ZERO_WINDOWS).ok(),
            generator:    Generator::new(),
            states:       HashMap::new(),
        }
    }

    pub fn add(&mut self, flow: &Flow) {
        let this = self.this(flow);

        if this.payload.is_none() && !flow.payload.is_empty() {
            this.payload = Some(flow.timestamp);

            if let Some(&mut State{payload: Some(ts), ..}) = self.peer(flow) {
                this.latency = Some(flow.timestamp - ts);
            }
        }

        if let Transport::TCP{ seq, flags, window, .. } = flow.transport {
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
            } else if ack && this.rtt.is_none() && this.syn.is_some() {
                if let Some(&mut State{syn: Some(syn), ..}) = self.peer(flow) {
                    this.rtt = Some(RTT::Client(flow.timestamp - syn));
                }
            }

            if this.fin.is_some() {
                if let Some(&mut State{fin: Some(..), ..}) = self.peer(flow) {
                    self.states.remove(&Key(flow.protocol, flow.src, flow.dst));
                    self.states.remove(&Key(flow.protocol, flow.dst, flow.src));
                    return;
                }
            } else if fin {
                this.fin = Some(flow.timestamp);
            }

            if ack && !syn {
                let size  = window.size;
                let scale = this.window.scale;

                this.window.size = size << scale;

                if this.window.size == 0 {
                    this.zwindows += 1;
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
                    this.retransmits.add(seq);
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

    pub fn append(&mut self, key: &Key, cs: &mut Customs) {
        if let Some(ref mut this) = self.states.get_mut(key) {
            if this.id != 0 {
                self.conn_id.map(|id| cs.add_u32(id, this.id));
            }

            match this.rtt {
                Some(RTT::Client(d)) => self.cli_latency.map(|id| cs.add_latency(id, d / 2)),
                Some(RTT::Server(d)) => self.srv_latency.map(|id| cs.add_latency(id, d / 2)),
                None                 => None,
            };

            if let Some(d) = this.latency {
                self.fpx_latency.map(|id| cs.add_latency(id, d));
            }

            let (retransmits, repeats) = this.retransmits.get();
            this.retransmits.reset();

            if retransmits > 0 {
                self.retx_out.map(|id| cs.add_u32(id, retransmits));
            }

            if repeats > 0 {
                self.retx_repeats.map(|id| cs.add_u32(id, repeats));
            }

            if this.ooorder > 0 {
                self.ooorder_in.map(|id| cs.add_u32(id, this.ooorder));
                this.ooorder = 0;
            }

            if this.syn.is_some() {
                self.rwindow.map(|id| cs.add_u32(id, this.window.size));
            }

            if this.zwindows > 0 {
                self.zwindows.map(|id| cs.add_u32(id, this.zwindows));
                this.zwindows = 0;
            }
        }
    }

    pub fn clear(&mut self, ts: Timestamp) {
        let timeout = Duration::seconds(60);
        self.states.retain(|_, s| (ts - s.last) < timeout);
    }

    fn this<'a>(&mut self, flow: &Flow) -> &'a mut State {
        let key = Key(flow.protocol, flow.src, flow.dst);
        let gen = &mut self.generator;
        let s = self.states.entry(key).or_insert_with(|| {
            let (id, seq, win) = match flow.transport {
                Transport::TCP{seq, window, ..} => (gen.id(flow), seq, window),
                Transport::UDP                  => (gen.id(flow), 0, Window::default()),
                _                               => (0,            0, Window::default()),
            };

            State{
                id:          id,
                latency:     None,
                rtt:         None,
                syn:         None,
                payload:     None,
                fin:         None,
                seq:         seq,
                window:      win,
                retransmits: Retransmits::new(seq),
                ooorder:     0,
                zwindows:    0,
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

impl Retransmits {
    fn new(seq: u32) -> Self {
        Retransmits{
            serial:  0,
            total:   0,
            repeats: 0,
            seq:     seq,
        }
    }

    fn add(&mut self, seq: u32) {
        self.total += 1;

        if seq == self.seq {
            self.serial += 1;
        } else {
            self.serial = 0;
            self.seq    = seq;
        }

        if self.serial == 3 {
            self.repeats += 1;
        }
    }

    fn get(&self) -> (u32, u32) {
        (self.total, self.repeats)
    }

    fn reset(&mut self) {
        self.total   = 0;
        self.repeats = 0;
    }
}

#[cfg(test)]
impl Tracker {
    pub fn latency(&self, key: &Key) -> Option<Duration> {
        self.states.get(key).and_then(|s| s.latency)
    }

    pub fn retransmits(&self, key: &Key) -> Option<(u32, u32)> {
        self.states.get(key).map(|s| s.retransmits.get())
    }

    pub fn ooorder(&self, key: &Key) -> Option<u32> {
        self.states.get(key).map(|s| s.ooorder)
    }

    pub fn zwindows(&self, key: &Key) -> Option<u32> {
        self.states.get(key).map(|s| s.zwindows)
    }
}
