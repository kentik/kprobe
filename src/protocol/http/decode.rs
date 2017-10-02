use std::collections::HashMap;
use std::ffi::CString;
use time::Duration;
use flow::{Addr, Flow, Timestamp};
use custom::*;
use super::conn::{Connection, Res};

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
    pub fn new(cs: &Customs) -> Result<Decoder, ()> {
        Ok(Decoder{
            req_url:     cs.get(HTTP_URL)?,
            req_host:    cs.get(HTTP_HOST)?,
            req_referer: cs.get(HTTP_REFERER)?,
            req_ua:      cs.get(HTTP_UA)?,
            res_status:  cs.get(HTTP_STATUS)?,
            latency:     cs.get(APP_LATENCY)?,
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
