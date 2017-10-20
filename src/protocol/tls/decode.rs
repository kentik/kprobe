use std::collections::HashMap;
use std::collections::hash_map::Entry::*;
use std::collections::hash_map::VacantEntry;
use time::Duration;
use flow::{Addr, Flow, Key, Timestamp, SYN, FIN};
use custom::*;
use super::conn::Connection;

pub struct Decoder {
    server_name:  u64,
    server_ver:   Option<u64>,
    cipher_suite: Option<u64>,
    conns:        HashMap<(Addr, Addr), Connection>,
}

impl Decoder {
    pub fn new(cs: &Customs) -> Result<Decoder, ()> {
        Ok(Decoder{
            server_name:  cs.get(TLS_SERVER_NAME)?,
            server_ver:   cs.get(TLS_SERVER_VERSION).ok(),
            cipher_suite: cs.get(TLS_CIPHER_SUITE).ok(),
            conns:        HashMap::new(),
        })
    }

    pub fn decode(&mut self, flow: &Flow, _cs: &mut Customs) -> bool {
        if let Some(conn) = self.conn(flow.src, flow.dst, flow.tcp_flags()) {
            conn.parse(flow.timestamp, flow.payload);
        }

        if flow.tcp_flags() & FIN == FIN {
            self.conns.remove(&(flow.src, flow.dst));
            self.conns.remove(&(flow.dst, flow.src));
        }

        false
    }

    pub fn append(&mut self, key: &Key, cs: &mut Customs) {
        let server_name  = self.server_name;
        let server_ver   = self.server_ver;
        let cipher_suite = self.cipher_suite;

        if let Some(conn) = self.conn(key.1, key.2, 0) {
            let state = conn.state();

            state.host_name.as_ref().map(|name| cs.add_str(server_name, name));

            state.server_ver.and_then(|ver| server_ver.map(|id| {
                let major = ver.0 as u32;
                let minor = ver.1 as u32;
                cs.add_u32(id, major << 8 | minor);
            }));

            state.cipher_suite.and_then(|suite| cipher_suite.map(|id| {
                cs.add_u32(id, suite.0 as u32);
            }));
        }
    }

    pub fn clear(&mut self, ts: Timestamp, timeout: Duration) {
        self.conns.retain(|_, c| !c.is_idle(ts, timeout))
    }

    fn conn<'a>(&'a mut self, src: Addr, dst: Addr, flags: u16) -> Option<&'a mut Connection> {
        let key = match src.port < dst.port {
            true  => (src, dst),
            false => (dst, src),
        };

        let maybe_insert = |e: VacantEntry<'a, _, _>| -> Option<&'a mut Connection> {
            match flags & SYN {
                SYN => Some(e.insert(Connection::new())),
                _   => None,
            }
        };

        match self.conns.entry(key) {
            Vacant(e)   => maybe_insert(e),
            Occupied(e) => Some(e.into_mut()),
        }
    }
}
