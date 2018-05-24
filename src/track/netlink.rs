use std::collections::HashMap;
use std::mem;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration as StdDuration};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use time::Duration;
use nell::api::diag;
use nell::ffi::*;
use custom::*;
use flow::*;
use track::id::Generator;

pub struct Tracker {
    conn_id:     Option<u64>,
    app_latency: Option<u64>,
    retx_out:    Option<u64>,
    generator:   Generator,
    states:      Arc<RwLock<HashMap<Key, State>>>,
}

#[derive(Debug)]
pub struct State {
    id:   u32,
    rtt:  Duration,
    retx: u32,
    last: Timestamp,
}

impl Tracker {
    pub fn new(cs: &Customs) -> Self {
        let states  = Arc::new(RwLock::new(HashMap::new()));
        let states2 = states.clone();

        thread::spawn(|| {
            let interval = StdDuration::from_millis(500);
            poll(interval, states2);
        });

        Tracker {
            conn_id:     cs.get(CONNECTION_ID).ok(),
            app_latency: cs.get(APP_LATENCY).ok(),
            retx_out:    cs.get(RETRANSMITTED_OUT).ok(),
            generator:   Generator::new(),
            states:      states.clone(),
        }
    }

    pub fn add(&mut self, flow: &Flow) {
        let mut states = self.states.write().unwrap();
        let state = states.entry(flow.key()).or_insert_with(|| {
            State {
                id:   self.generator.id(flow),
                rtt:  Duration::milliseconds(0),
                retx: 0,
                last: Timestamp::zero(),
            }
        });
        state.last = flow.timestamp;
    }

    pub fn append(&mut self, key: &Key, cs: &mut Customs) {
        let mut states = self.states.write().unwrap();
        if let Some(this) = states.get_mut(key) {
            if this.id != 0 {
                self.conn_id.map(|id| cs.add_u32(id, this.id));
            }

            self.app_latency.map(|id| cs.add_latency(id, this.rtt));

            if this.retx > 0 {
                self.retx_out.map(|id| cs.add_u32(id, this.retx));
                this.retx = 0;
            }
        }
    }

    pub fn clear(&mut self, ts: Timestamp) {
        let timeout = Duration::seconds(60);
        let mut states = self.states.write().unwrap();
        states.retain(|_, s| (ts - s.last) < timeout);
    }
}

fn poll(interval: StdDuration, states: Arc<RwLock<HashMap<Key, State>>>) {
    let mut old: HashMap<Key, tcp_info_3_16> = HashMap::new();
    let mut new: HashMap<Key, tcp_info_3_16> = HashMap::new();

    loop {
        let mut req = inet_diag_req_v2 {
            idiag_states: !0 & !(1 << 6 | 1 << 7 | 1 << 8),
            idiag_ext:    1 << (INET_DIAG_INFO as u8 - 1),
            .. Default::default()
        };

        for &family in &[AF_INET, AF_INET6] {
            req.sdiag_family   = family;
            req.sdiag_protocol = IPPROTO_TCP;

            for diag in diag::diag::<tcp_info_3_16>(&mut req).unwrap() {
                if let Some(info) = diag.info {
                    let src = addr(&diag.src);
                    let dst = addr(&diag.dst);
                    let key = Key(Protocol::TCP, src, dst);
                    new.insert(key, info);
                }
            }
        }

        for (key, state) in states.write().unwrap().iter_mut() {
            if let (Some(new), Some(old)) = (new.get(key), old.get(key)) {
                state.rtt   = Duration::microseconds(new.tcpi_rtt as i64);
                state.retx += new.tcpi_total_retrans - old.tcpi_total_retrans;
            }
        }

        mem::swap(&mut old, &mut new);
        new.clear();

        thread::sleep(interval);
    }
}

fn addr(addr: &SocketAddr) -> Addr {
    fn ipv4(ip: Ipv4Addr) -> IpAddr {
        IpAddr::V4(ip)
    }

    fn ipv6(ip: Ipv6Addr) -> IpAddr {
        match ip.to_ipv4() {
            Some(ip) => IpAddr::V4(ip),
            None     => IpAddr::V6(ip),
        }
    }

    match addr {
        SocketAddr::V4(s) => Addr{addr: ipv4(*s.ip()), port: s.port()},
        SocketAddr::V6(s) => Addr{addr: ipv6(*s.ip()), port: s.port()},
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct tcp_info_3_16 {
    pub tcpi_state:           u8,
    pub tcpi_ca_state:        u8,
    pub tcpi_retransmits:     u8,
    pub tcpi_probes:          u8,
    pub tcpi_backoff:         u8,
    pub tcpi_options:         u8,
    pub _bitfield_1:          [u8; 2usize],
    pub tcpi_rto:             u32,
    pub tcpi_ato:             u32,
    pub tcpi_snd_mss:         u32,
    pub tcpi_rcv_mss:         u32,
    pub tcpi_unacked:         u32,
    pub tcpi_sacked:          u32,
    pub tcpi_lost:            u32,
    pub tcpi_retrans:         u32,
    pub tcpi_fackets:         u32,
    pub tcpi_last_data_sent:  u32,
    pub tcpi_last_ack_sent:   u32,
    pub tcpi_last_data_recv:  u32,
    pub tcpi_last_ack_recv:   u32,
    pub tcpi_pmtu:            u32,
    pub tcpi_rcv_ssthresh:    u32,
    pub tcpi_rtt:             u32,
    pub tcpi_rttvar:          u32,
    pub tcpi_snd_ssthresh:    u32,
    pub tcpi_snd_cwnd:        u32,
    pub tcpi_advmss:          u32,
    pub tcpi_reordering:      u32,
    pub tcpi_rcv_rtt:         u32,
    pub tcpi_rcv_space:       u32,
    pub tcpi_total_retrans:   u32,
    pub tcpi_pacing_rate:     u64,
    pub tcpi_max_pacing_rate: u64,
}
