use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::ffi::CString;
use std::net::Ipv4Addr;
use time::Duration;
use nom::IResult::Done;
use pnet::util::MacAddr;
use super::parser::{self, Opt};
use crate::flow::Timestamp;

pub struct Connection {
    last:   Timestamp,
    state:  State,
}

#[derive(Debug, Default)]
struct State {
    pending: HashMap<u64, Timestamp>,
    hasher:  RandomState,
}

#[derive(Debug)]
pub struct Message {
    pub op:      u8,
    pub msg:     u8,
    pub xid:     u32,
    pub ciaddr:  Ipv4Addr,
    pub yiaddr:  Ipv4Addr,
    pub siaddr:  Ipv4Addr,
    pub chaddr:  CString,
    pub host:    Option<CString>,
    pub domain:  Option<CString>,
    pub lease:   Option<Duration>,
    pub latency: Option<Duration>,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            last:  Timestamp::zero(),
            state: Default::default(),
        }
    }

    pub fn parse(&mut self, ts: Timestamp, buf: &[u8]) -> Option<Message> {
        let state = &mut self.state;
        match parser::message(buf) {
            Done(_, msg) => Some(state.update(msg, ts)),
            _            => None,
        }
    }

    pub fn is_idle(&self, ts: Timestamp, timeout: Duration) -> bool {
        self.state.pending.is_empty() || (ts - self.last) > timeout
    }
}

impl State {
    fn update(&mut self, m: parser::Message, ts: Timestamp) -> Message {
        let key = self.key(&m);
        let latency = if m.op == 1 {
            self.pending.insert(key, ts);
            None
        } else {
            self.pending.remove(&key).map(|ts0| ts0 - ts)
        };

        options(Message{
            op:      m.op,
            msg:     0,
            xid:     m.xid,
            ciaddr:  m.ciaddr,
            yiaddr:  m.yiaddr,
            siaddr:  m.siaddr,
            chaddr:  chaddr(m.chaddr),
            host:    None,
            domain:  None,
            lease:   None,
            latency: latency,
        }, m.opts)
    }

    fn key(&mut self, m: &parser::Message) -> u64 {
        let mut s = self.hasher.build_hasher();
        m.chaddr.hash(&mut s);
        m.xid.hash(&mut s);
        s.finish()
    }
}

fn options(mut msg: Message, opts: Vec<Opt>) -> Message {
    for o in opts {
        match o {
            Opt::Type(t)   => msg.msg    = t,
            Opt::Host(s)   => msg.host   = CString::new(s).ok(),
            Opt::Domain(s) => msg.domain = CString::new(s).ok(),
            Opt::Lease(s)  => msg.lease  = Some(Duration::seconds(s as i64)),
            _              => (),
        }
    }
    msg
}

fn chaddr(addr: &[u8]) -> CString {
    if addr.len() == 6 {
        let (a, b, c) = (addr[0], addr[1], addr[2]);
        let (d, e, f) = (addr[3], addr[4], addr[5]);
        let mac = MacAddr::new(a, b, c, d, e, f);
        CString::new(format!("{}", mac))
    } else {
        CString::new("")
    }.unwrap()
}
