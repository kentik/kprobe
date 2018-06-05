use std::collections::HashMap;
use std::collections::hash_map::Entry::*;
use std::collections::hash_map::VacantEntry;
use std::ffi::CString;
use fnv::FnvHashMap;
use time::Duration;
use flow::{Addr, Flow, Timestamp, SYN, ACK, FIN};
use custom::*;
use super::conn::Connection;

pub struct Decoder {
    req_url:     u64,
    req_host:    u64,
    req_referer: u64,
    req_ua:      u64,
    res_status:  u64,
    latency:     u64,
    empty:       CString,
    conns:       FnvHashMap<(Addr, Addr), Connection>,
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
            conns:       FnvHashMap::default(),
        })
    }

    pub fn decode(&mut self, flow: &Flow, cs: &mut Customs) -> bool {
        let flags = flow.tcp_flags();
        let decoded = match self.conn(flow.src, flow.dst, flags) {
            Some(ref mut c) if c.is_client(flow) => self.parse_req(c, flow, cs),
            Some(ref mut c)                      => self.parse_res(c, flow, cs),
            None                                 => false,
        };

        if !decoded && !flow.payload.is_empty() && flags & FIN == FIN {
            let mut flow = flow.clone();
            flow.payload = &[];
            self.decode(&flow, cs)
        } else {
            decoded
        }
    }

    pub fn clear(&mut self, ts: Timestamp, timeout: Duration) {
        self.conns.retain(|_, c| !c.is_idle(ts, timeout))
    }

    fn conn<'a>(&mut self, src: Addr, dst: Addr, flags: u16) -> Option<&'a mut Connection> {
        let key = match src.port < dst.port {
            true  => (src, dst),
            false => (dst, src),
        };

        let maybe_insert = |e: VacantEntry<'a, _, _>| -> Option<&'a mut Connection> {
            const SYNACK: u16 = SYN|ACK;
            match flags & SYNACK {
                SYN    => Some(e.insert(Connection::new(dst.port))),
                SYNACK => Some(e.insert(Connection::new(src.port))),
                _      => None,
            }
        };

        // safe because self.conns will not be accessed in parse_req or parse_res
        let conns: &'a mut HashMap<_, _, _> = unsafe {
            &mut *(&mut self.conns as *mut HashMap<_, _, _>)
        };

        match conns.entry(key) {
            Vacant(e)   => maybe_insert(e),
            Occupied(e) => Some(e.into_mut()),
        }
    }

    fn parse_req(&self, c: &mut Connection, flow: &Flow, cs: &mut Customs) -> bool {
        let req_url     = self.req_url;
        let req_host    = self.req_host;
        let req_referer = self.req_referer;
        let req_ua      = self.req_ua;
        let empty       = &self.empty;

        c.parse_req(flow.timestamp, flow.payload).map(|req| {
            // println!("got http request {:#?}", req);
            cs.add_str(req_url, req.url.as_ref().unwrap_or(empty));
            cs.add_str(req_host, req.host.as_ref().unwrap_or(empty));
            cs.add_str(req_referer, req.referer.as_ref().unwrap_or(empty));
            cs.add_str(req_ua, req.ua.as_ref().unwrap_or(empty));
            true
        }).unwrap_or(false)
    }

    fn parse_res(&self, c: &mut Connection, flow: &Flow, cs: &mut Customs) -> bool {
        let req_url     = self.req_url;
        let req_host    = self.req_host;
        let req_referer = self.req_referer;
        let req_ua      = self.req_ua;
        let res_status  = self.res_status;
        let latency     = self.latency;
        let empty       = &self.empty;

        c.parse_res(flow.timestamp, flow.payload).map(|res| {
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
