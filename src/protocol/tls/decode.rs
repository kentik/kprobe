use std::collections::{HashMap, HashSet};
use time::Duration;
use flow::{Addr, Flow, Key, Timestamp};
use libkflow::kflowCustom;
use custom::Customs;
use super::conn::Connection;

const KFLOW_HTTP_HOST: &str = "KFLOW_HTTP_HOST";

pub struct Decoder {
    server_name: u64,
    conns:       HashMap<(Addr, Addr), Connection>,
}

impl Decoder {
    pub fn new(cs: &[kflowCustom]) -> Option<Decoder> {
        let mut ns = HashSet::new();
        ns.insert(KFLOW_HTTP_HOST);

        let cs = cs.iter().filter_map(|c| {
            ns.get(c.name()).map(|n| (*n, c.id))
        }).collect::<HashMap<_, _>>();

        if ns.len() != cs.len() {
            return None;
        }

        Some(Decoder{
            server_name: cs[KFLOW_HTTP_HOST],
            conns:       HashMap::new(),
        })
    }

    pub fn decode(&mut self, flow: &Flow, _cs: &mut Customs) -> bool {
        let conn = self.conn(flow.src, flow.dst);
        conn.parse(flow.timestamp, flow.payload);
        false
    }

    pub fn append(&mut self, key: &Key, cs: &mut Customs) {
        let server_name = self.server_name;
        let state = self.conn(key.1, key.2).state();
        state.host_name.as_ref().map(|name| cs.add_str(server_name, name));
    }

    pub fn clear(&mut self, ts: Timestamp, timeout: Duration) {
        self.conns.retain(|_, c| !c.is_idle(ts, timeout))
    }

    fn conn(&mut self, src: Addr, dst: Addr) -> &mut Connection {
        self.conns.entry(match src.port < dst.port {
            true  => (src, dst),
            false => (dst, src),
        }).or_insert_with(Connection::new)
    }
}
