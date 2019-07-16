use std::ffi;
use super::parser;
use crate::flow;
use nom::IResult::Done;

use crate::flow::Timestamp;
use std::hash::{BuildHasher, Hash, Hasher};

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::net;
use std::default::Default;
use time;

#[derive(Default)]
pub struct Message {
    pub code:            u8,
    pub id:              u8,
    pub length:          u16,
    pub user:            Option<ffi::CString>,
    pub service_type:    Option<u8>,
    pub framed_ip:       Option<net::IpAddr>,
    pub framed_mask:     Option<u32>,
    pub framed_proto:    Option<u32>,
    pub acct_session_id: Option<ffi::CString>,
    pub acct_status:     Option<u32>,
}

impl<'a> From<parser::Message<'a>> for Message {
    fn from(m: parser::Message) -> Self {
        let mut ret = Self {
            code:         m.code.into(),
            id:           m.id,
            length:       m.len,
            ..Default::default()
        };

        for attr in m.attrs {
            match attr {
                parser::Attr::UserName(n)        => ret.user = ffi::CString::new(n.as_bytes()).ok(),
                parser::Attr::ServiceType(t)     => ret.service_type = Some(t.into()),
                parser::Attr::FramedIPAddr(ip)   => ret.framed_ip = Some(net::IpAddr::from(ip)),
                parser::Attr::FramedIPMask(mask) => ret.framed_mask = Some(mask.into()),
                parser::Attr::FramedProtocol(p)  => ret.framed_proto = Some(p.into()),
                parser::Attr::AcctSessionID(sid) => ret.acct_session_id = ffi::CString::new(sid.as_bytes()).ok(),
                parser::Attr::AcctStatusType(s)  => ret.acct_status = Some(s.into()),
                _                                => (),
            }
        }

        ret
    }
}

pub fn parse(flow: &flow::Flow) -> Option<Message> {
    match parser::message(flow.payload) {
        Done(_, msg) => Some(msg),
        _            => None,
    }.map(Message::from)
}

#[derive(Debug, Default)]
pub struct Tracker {
    pending: HashMap<u64, Timestamp>,
    hasher: RandomState,
}

impl Tracker {
    pub fn new() -> Self {
        Self { ..Default::default() }
    }

    pub fn observe(&mut self, m: &Message, src: crate::flow::Addr, dst: crate::flow::Addr, ts: Timestamp) -> Option<time::Duration> {
        match m.code {
            1 | 4 => {
                let key = self.key(src, dst, m.id);
                self.pending.insert(key, ts);
                None
            },
            _     => {
                let key = self.key(dst, src, m.id);
                self.pending.remove(&key).map(|ts0| ts - ts0)
            }
        }
    }

    fn key(&mut self, src: crate::flow::Addr, dst: crate::flow::Addr, id: u8) -> u64 {
        let mut s = self.hasher.build_hasher();
        src.hash(&mut s);
        dst.hash(&mut s);
        id.hash(&mut s);
        s.finish()
    }
}
