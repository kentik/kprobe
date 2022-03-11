use std::collections::HashMap;
use std::ffi::CString;
use time::Duration;
use crate::flow::{Addr, Flow};
use crate::custom::*;
use crate::time::Timestamp;
use super::conn::{Connection, Message};

pub struct Decoder {
    query_name: u64,
    query_type: u64,
    reply_code: u64,
    reply_data: u64,
    latency:    u64,
    name_str:   Option<CString>,
    data_str:   Option<CString>,
    empty:      CString,
    conns:      HashMap<(Addr, Addr), Connection>,
}

impl Decoder {
    pub fn new(cs: &Customs) -> Result<Decoder, ()> {
        Ok(Decoder{
            query_name: cs.get(DNS_QUERY_NAME)?,
            query_type: cs.get(DNS_QUERY_TYPE)?,
            reply_code: cs.get(DNS_REPLY_CODE)?,
            reply_data: cs.get(DNS_REPLY_DATA)?,
            latency:    cs.get(APP_LATENCY)?,
            name_str:   None,
            data_str:   None,
            empty:      Default::default(),
            conns:      HashMap::new(),
        })
    }

    pub fn decode(&mut self, flow: &Flow, cs: &mut Customs) -> bool {
        //println!("extracting DNS flow from {:?}", flow);
        self.parse(flow).map(move |msg| {
            match msg {
                Message::Query(qq) => {
                    self.name_str = CString::new(qq.qname).ok();
                    cs.add_str(self.query_name, self.name_str.as_ref().unwrap_or(&self.empty));
                    cs.add_u32(self.query_type, qq.qtype as u32);
                    true
                },
                Message::Reply(qq, rc, data, d) => {
                    self.name_str = CString::new(qq.qname).ok();
                    self.data_str = CString::new(data).ok();
                    cs.add_str(self.query_name, self.name_str.as_ref().unwrap_or(&self.empty));
                    cs.add_u32(self.query_type, qq.qtype as u32);
                    cs.add_u32(self.reply_code, rc as u32);
                    cs.add_str(self.reply_data, self.data_str.as_ref().unwrap_or(&self.empty));
                    cs.add_u32(self.latency, d.num_milliseconds() as u32);
                    true
                },
            }
        }).unwrap_or(false)
    }

    pub fn clear(&mut self, ts: Timestamp, timeout: Duration) {
        self.conns.retain(|_, c| !c.is_idle(ts, timeout))
    }

    fn parse(&mut self, flow: &Flow) -> Option<Message> {
        let addr = match (flow.src, flow.dst) {
            (src, dst) if dst.port == 53 => (src, dst),
            (src, dst) if src.port == 53 => (dst, src),
            _                            => unreachable!(),
        };
        self.conns.entry(addr).or_insert_with(Connection::new).parse(flow.timestamp, flow.payload)
    }
}
