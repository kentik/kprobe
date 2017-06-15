use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use time::Duration;
use flow::{Addr, Flow, Timestamp};
use libkflow::kflowCustom;
use custom::Customs;
use super::conn::{Connection, Res};

const APPL_LATENCY_MS:       &str = "APPL_LATENCY_MS";
const KFLOW_HTTP_URL:        &str = "KFLOW_HTTP_URL";
const KFLOW_HTTP_HOST:       &str = "KFLOW_HTTP_HOST";
const KFLOW_HTTP_REFERER:    &str = "KFLOW_HTTP_REFERER";
const KFLOW_HTTP_USER_AGENT: &str = "KFLOW_HTTP_UA";
const KFLOW_HTTP_STATUS:     &str = "KFLOW_HTTP_STATUS";

pub struct Decoder {
    req_url:     u64,
    req_host:    u64,
    req_referer: u64,
    req_ua:      u64,
    res_status:  u64,
    latency:     u64,
    empty:       CString,
    res:         Option<Res>,
    conns:       HashMap<(Addr, Addr), Connection>,
}

impl Decoder {
    pub fn new(cs: &[kflowCustom]) -> Option<Decoder> {
        let mut ns = HashSet::new();
        ns.insert(APPL_LATENCY_MS);
        ns.insert(KFLOW_HTTP_URL);
        ns.insert(KFLOW_HTTP_HOST);
        ns.insert(KFLOW_HTTP_REFERER);
        ns.insert(KFLOW_HTTP_USER_AGENT);
        ns.insert(KFLOW_HTTP_STATUS);

        let cs = cs.iter().filter_map(|c| {
            ns.get(c.name()).map(|n| (*n, c.id))
        }).collect::<HashMap<_, _>>();

        if ns.len() != cs.len() {
            return None;
        }

        Some(Decoder{
            req_url:     cs[KFLOW_HTTP_URL],
            req_host:    cs[KFLOW_HTTP_HOST],
            req_referer: cs[KFLOW_HTTP_REFERER],
            req_ua:      cs[KFLOW_HTTP_USER_AGENT],
            res_status:  cs[KFLOW_HTTP_STATUS],
            latency:     cs[APPL_LATENCY_MS],
            empty:       Default::default(),
            res:         None,
            conns:       HashMap::new(),
        })
    }

    pub fn decode(&mut self, flow: &Flow, cs: &mut Customs) -> bool {
        match (flow.src.port, flow.dst.port) {
            (_, 80) => self.parse_req(flow, cs),
            (80, _) => self.parse_res(flow, cs),
            _       => false,
        }
    }

    pub fn clear(&mut self, ts: Timestamp, timeout: Duration) {
        self.conns.retain(|_, c| !c.is_idle(ts, timeout))
    }

    fn parse_req(&mut self, flow: &Flow, cs: &mut Customs) -> bool {
        let addr = (flow.src, flow.dst);
        let conn = self.conns.entry(addr).or_insert_with(Connection::new);

        let req_url     = self.req_url;
        let req_host    = self.req_host;
        let req_referer = self.req_referer;
        let req_ua      = self.req_ua;
        let empty       = &self.empty;

        conn.parse_req(flow.timestamp, flow.payload).map(|req| {
            // println!("got http request {:#?}", req);
            cs.add_str(req_url, req.url.as_ref().unwrap_or(empty));
            cs.add_str(req_host, req.host.as_ref().unwrap_or(empty));
            cs.add_str(req_referer, req.referer.as_ref().unwrap_or(empty));
            cs.add_str(req_ua, req.ua.as_ref().unwrap_or(empty));
            true
        }).unwrap_or(false)
    }

    fn parse_res(&mut self, flow: &Flow, cs: &mut Customs) -> bool {
        let addr = (flow.dst, flow.src);
        let conn = self.conns.entry(addr).or_insert_with(Connection::new);

        self.res = conn.parse_res(flow.timestamp, flow.payload);

        let req_url     = self.req_url;
        let req_host    = self.req_host;
        let req_referer = self.req_referer;
        let req_ua      = self.req_ua;
        let res_status  = self.res_status;
        let latency     = self.latency;
        let empty       = &self.empty;

        self.res.as_ref().map(|res| {
            // println!("got http response {:#?}", res);
            cs.add_str(req_url, res.url.as_ref().unwrap_or(empty));
            cs.add_str(req_host, res.host.as_ref().unwrap_or(empty));
            cs.add_str(req_referer, res.referer.as_ref().unwrap_or(empty));
            cs.add_str(req_ua, res.ua.as_ref().unwrap_or(empty));
            cs.add_u32(res_status, res.status as u32);
            cs.add_u32(latency, res.latency.num_milliseconds() as u32);
            true
        }).unwrap_or(false)
    }
}
