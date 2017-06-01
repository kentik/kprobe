use time::Duration;
use flow::{Flow, Timestamp};
use flow::Protocol::*;
use libkflow::kflowCustom;
use protocol::*;

#[derive(Debug, Clone, Copy)]
pub enum Decoder {
    DNS, HTTP, Postgres, None
}

pub struct Decoders {
    dns:      Option<dns::Decoder>,
    http:     Option<http::Decoder>,
    postgres: Option<postgres::Decoder>,
}

impl Decoders {
    pub fn new(cs: &[kflowCustom]) -> Self {
        Decoders {
            dns:      dns::Decoder::new(&cs),
            http:     http::Decoder::new(&cs),
            postgres: postgres::Decoder::new(&cs),
        }
    }

    pub fn classify(&self, flow: &Flow) -> Decoder {
        match (flow.protocol, flow.src.port, flow.dst.port) {
            (UDP, 53, _)   if self.dns.is_some()      => Decoder::DNS,
            (UDP, _, 53)   if self.dns.is_some()      => Decoder::DNS,
            (TCP, 80, _)   if self.http.is_some()     => Decoder::HTTP,
            (TCP, _, 80)   if self.http.is_some()     => Decoder::HTTP,
            (TCP, 5432, _) if self.postgres.is_some() => Decoder::Postgres,
            (TCP, _, 5432) if self.postgres.is_some() => Decoder::Postgres,
            _                                         => Decoder::None,
        }
    }

    pub fn decode(&mut self, d: Decoder, flow: &Flow, cs: &mut Customs) -> bool {
        if flow.payload.is_empty() {
            return false
        }

        match d {
            Decoder::DNS      => self.dns.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::Postgres => self.postgres.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::HTTP     => self.http.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::None     => None,
        }.unwrap_or(false)
    }

    pub fn clear(&mut self, ts: Timestamp) {
        let timeout = Duration::seconds(15);
        self.dns.as_mut().map(|d| d.clear(ts, timeout));
        self.http.as_mut().map(|d| d.clear(ts, timeout));
    }
}
