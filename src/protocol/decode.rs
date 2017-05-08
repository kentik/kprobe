use flow::Flow;
use flow::Protocol::*;
use libkflow::kflowCustom;
use protocol::dns;
use protocol::postgres;

#[derive(Debug, Clone, Copy)]
pub enum Decoder {
    DNS, Postgres, None
}

pub struct Decoders {
    dns:      Option<dns::Decoder>,
    postgres: Option<postgres::Decoder>,
}

impl Decoders {
    pub fn new(cs: Vec<kflowCustom>) -> Self {
        Decoders {
            dns:      dns::Decoder::new(cs.clone()),
            postgres: postgres::Decoder::new(cs.clone()),
        }
    }

    pub fn classify(&self, flow: &Flow) -> Decoder {
        match (flow.protocol, flow.src.port, flow.dst.port) {
            (UDP, 53, _)   if self.dns.is_some()      => Decoder::DNS,
            (UDP, _, 53)   if self.dns.is_some()      => Decoder::DNS,
            (TCP, 5432, _) if self.postgres.is_some() => Decoder::Postgres,
            (TCP, _, 5432) if self.postgres.is_some() => Decoder::Postgres,
            _                                         => Decoder::None,
        }
    }

    pub fn decode(&mut self, d: Decoder, flow: &Flow) -> Option<&[kflowCustom]> {
        match d {
            Decoder::DNS      => self.dns.as_mut().and_then(|d| d.decode(flow)),
            Decoder::Postgres => self.postgres.as_mut().and_then(|d| d.decode(flow)),
            Decoder::None     => None,
        }
    }
}
