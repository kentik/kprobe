use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use flow::{Addr, Flow};
use libkflow::kflowCustom;
use protocol::Customs;
use super::conn::{Connection, Message};

const APPL_LATENCY_MS:      &str = "APPL_LATENCY_MS";
const KFLOW_DNS_QUERY:      &str = "KFLOW_DNS_QUERY";
const KFLOW_DNS_QUERY_TYPE: &str = "KFLOW_DNS_QUERY_TYPE";
const KFLOW_DNS_RET_CODE:   &str = "KFLOW_DNS_RET_CODE";
const KFLOW_DNS_RESPONSE:   &str = "KFLOW_DNS_RESPONSE";

pub struct Decoder {
    query_name: u64,
    query_type: u64,
    reply_code: u64,
    reply_data: u64,
    latency:    u64,
    name_str:   CString,
    data_str:   CString,
    conns:      HashMap<(Addr, Addr), Connection>,
}

impl Decoder {
    pub fn new(cs: &[kflowCustom]) -> Option<Decoder> {
        let mut ns = HashSet::new();
        ns.insert(APPL_LATENCY_MS);
        ns.insert(KFLOW_DNS_QUERY);
        ns.insert(KFLOW_DNS_QUERY_TYPE);
        ns.insert(KFLOW_DNS_RESPONSE);
        ns.insert(KFLOW_DNS_RET_CODE);

        let cs = cs.iter().filter_map(|c| {
            ns.get(c.name()).map(|n| (*n, c.id))
        }).collect::<HashMap<_, _>>();

        if ns.len() != cs.len() {
            return None;
        }

        Some(Decoder{
            query_name: cs[KFLOW_DNS_QUERY],
            query_type: cs[KFLOW_DNS_QUERY_TYPE],
            reply_code: cs[KFLOW_DNS_RET_CODE],
            reply_data: cs[KFLOW_DNS_RESPONSE],
            latency:    cs[APPL_LATENCY_MS],
            name_str:   Default::default(),
            data_str:   Default::default(),
            conns:      HashMap::new(),
        })
    }

    pub fn decode(&mut self, flow: &Flow, cs: &mut Customs) -> bool {
        //println!("extracting DNS flow from {:?}", flow);
        self.parse(flow).map(move |msg| {
            match msg {
                Message::Query(qq) => {
                    self.name_str = CString::new(qq.qname).unwrap();
                    cs.add_str(self.query_name, &self.name_str);
                    cs.add_u32(self.query_type, qq.qtype as u32);
                    true
                },
                Message::Reply(qq, rc, data, d) => {
                    self.name_str = CString::new(qq.qname).unwrap();
                    self.data_str = CString::new(data).unwrap();
                    cs.add_str(self.query_name, &self.name_str);
                    cs.add_u32(self.query_type, qq.qtype as u32);
                    cs.add_u32(self.reply_code, rc as u32);
                    cs.add_str(self.reply_data, &self.data_str);
                    cs.add_u32(self.latency, d.num_milliseconds() as u32);
                    true
                },
            }
        }).unwrap_or(false)
    }

    pub fn clear(&mut self) {
        self.conns.retain(|_, c| !c.is_idle())
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
