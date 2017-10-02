use std::collections::HashMap;
use flow::{Addr, Flow};
use custom::Customs;
use super::conn::{Connection, CompletedQuery};

pub struct Decoder {
    conns: HashMap<(Addr, Addr), Connection>,
}

impl Decoder {
    pub fn new(cs: &Customs) -> Option<Decoder> {
        let _ = cs;
        // FIXME: WIP
        None
    }

    pub fn decode(&mut self, flow: &Flow, cs: &mut Customs) -> bool {
        let queries = match (flow.src.port, flow.dst.port) {
            (_, 5432) => self.parse_fe(flow),
            (5432, _) => self.parse_be(flow),
            _         => None,
        };

        if let Some(queries) = queries {
            println!("got PostgreSQL queries {:?}", queries);
        }

        // FIXME: WIP
        let _ = cs;
        false
    }

    fn parse_fe(&mut self, flow: &Flow) -> Option<Vec<CompletedQuery>> {
        let addr = (flow.src, flow.dst);
        let conn = self.conns.entry(addr).or_insert_with(Connection::new);
        conn.frontend_msg(flow.timestamp, flow.payload)
    }

    fn parse_be(&mut self, flow: &Flow) -> Option<Vec<CompletedQuery>> {
        let addr = (flow.dst, flow.src);
        let conn = self.conns.entry(addr).or_insert_with(Connection::new);
        conn.backend_msg(flow.timestamp, flow.payload)
    }
}
