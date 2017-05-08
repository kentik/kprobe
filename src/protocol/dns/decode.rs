use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::ptr;
use flow::{Addr, Flow};
use libkflow::kflowCustom;
use super::conn::{Connection, Message};

const APPL_LATENCY_MS:      &str = "APPL_LATENCY_MS";
const KFLOW_DNS_QUERY:      &str = "KFLOW_DNS_QUERY";
const KFLOW_DNS_QUERY_TYPE: &str = "KFLOW_DNS_QUERY_TYPE";
const KFLOW_DNS_RET_CODE:   &str = "KFLOW_DNS_RET_CODE";
const KFLOW_DNS_RESPONSE:   &str = "KFLOW_DNS_RESPONSE";

pub struct Decoder {
    query_cs:   Vec<kflowCustom>,
    reply_cs:   Vec<kflowCustom>,
    query_name: *mut kflowCustom,
    query_type: *mut kflowCustom,
    reply_name: *mut kflowCustom,
    reply_type: *mut kflowCustom,
    reply_code: *mut kflowCustom,
    reply_data: *mut kflowCustom,
    latency:    *mut kflowCustom,
    name_str:   CString,
    data_str:   CString,
    conns:      HashMap<(Addr, Addr), Connection>,
}

impl Decoder {
    pub fn new(cs: Vec<kflowCustom>) -> Option<Decoder> {
        let mut ns = HashSet::new();
        ns.insert(APPL_LATENCY_MS);
        ns.insert(KFLOW_DNS_QUERY);
        ns.insert(KFLOW_DNS_QUERY_TYPE);
        ns.insert(KFLOW_DNS_RESPONSE);
        ns.insert(KFLOW_DNS_RET_CODE);

        let mut reply_cs: Vec<kflowCustom> = Vec::new();

        for c in cs.into_iter() {
            if ns.contains(c.name()) {
                reply_cs.push(c);
            }
        }

        if ns.len() != reply_cs.len() {
            return None;
        }

        let mut query_cs = reply_cs.clone().into_iter().filter(|c| {
            c.name().starts_with("KFLOW_DNS_QUERY")
        }).collect::<Vec<_>>();

        let mut query_name: *mut kflowCustom = ptr::null_mut();
        let mut query_type: *mut kflowCustom = ptr::null_mut();
        let mut reply_name: *mut kflowCustom = ptr::null_mut();
        let mut reply_type: *mut kflowCustom = ptr::null_mut();
        let mut reply_code: *mut kflowCustom = ptr::null_mut();
        let mut reply_data: *mut kflowCustom = ptr::null_mut();
        let mut latency:    *mut kflowCustom = ptr::null_mut();

        for c in query_cs.iter_mut() {
            match c.name() {
                KFLOW_DNS_QUERY      => query_name = c,
                KFLOW_DNS_QUERY_TYPE => query_type = c,
                _                    => (),
            }
        }

        for c in reply_cs.iter_mut() {
            match c.name() {
                KFLOW_DNS_QUERY      => reply_name = c,
                KFLOW_DNS_QUERY_TYPE => reply_type = c,
                KFLOW_DNS_RET_CODE   => reply_code = c,
                KFLOW_DNS_RESPONSE   => reply_data = c,
                APPL_LATENCY_MS      => latency    = c,
                _                    => (),
            }
        }

        Some(Decoder{
            query_cs:   query_cs,
            reply_cs:   reply_cs,
            query_name: query_name,
            query_type: query_type,
            reply_name: reply_name,
            reply_type: reply_type,
            reply_code: reply_code,
            reply_data: reply_data,
            latency:    latency,
            name_str:   Default::default(),
            data_str:   Default::default(),
            conns:      HashMap::new(),
        })
    }

    pub fn decode(&mut self, flow: &Flow) -> Option<&[kflowCustom]> {
        //println!("extracting DNS flow from {:?}", flow);
        self.parse(flow).map(move |msg| {
            match msg {
                Message::Query(qq) => {
                    self.name_str = CString::new(qq.qname).unwrap();
                    unsafe { &mut *self.query_name }.set_str(&self.name_str);
                    unsafe { &mut *self.query_type }.set_u32(qq.qtype as u32);
                    &self.query_cs[..]
                },
                Message::Reply(qq, rc, data, d) => {
                    self.name_str = CString::new(qq.qname).unwrap();
                    self.data_str = CString::new(data).unwrap();
                    unsafe { &mut *self.reply_name }.set_str(&self.name_str);
                    unsafe { &mut *self.reply_type }.set_u32(qq.qtype as u32);
                    unsafe { &mut *self.reply_code }.set_u32(rc as u32);
                    unsafe { &mut *self.reply_data }.set_str(&self.data_str);
                    unsafe { &mut *self.latency    }.set_u32(d.num_milliseconds() as u32);
                    &self.reply_cs[..]
                },
            }
        })
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
