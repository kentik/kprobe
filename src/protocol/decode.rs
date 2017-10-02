use time::Duration;
use flow::{Flow, Key, Timestamp};
use flow::{FIN, SYN};
use flow::Protocol::*;
use custom::Customs;
use protocol::*;

#[derive(Debug, Clone, Copy)]
pub enum Decoder {
    DNS, HTTP, Postgres, TLS, None
}

#[derive(Default)]
pub struct Decoders {
    dns:      Option<dns::Decoder>,
    http:     Option<http::Decoder>,
    tls:      Option<tls::Decoder>,
    postgres: Option<postgres::Decoder>,
}

impl Decoders {
    pub fn new(cs: &Customs, decode: bool) -> Self {
        if !decode {
            return Default::default()
        }

        Decoders{
            dns:      dns::Decoder::new(cs).ok(),
            http:     http::Decoder::new(cs).ok(),
            tls:      tls::Decoder::new(cs).ok(),
            postgres: postgres::Decoder::new(cs),
        }
    }

    pub fn classify(&self, flow: &Flow) -> Decoder {
        match (flow.protocol, flow.src.port, flow.dst.port) {
            (UDP, 53, _)   if self.dns.is_some()      => Decoder::DNS,
            (UDP, _, 53)   if self.dns.is_some()      => Decoder::DNS,
            (TCP, 80, _)   if self.http.is_some()     => Decoder::HTTP,
            (TCP, _, 80)   if self.http.is_some()     => Decoder::HTTP,
            (TCP, 443, _)  if self.tls.is_some()      => Decoder::TLS,
            (TCP, _, 443)  if self.tls.is_some()      => Decoder::TLS,
            (TCP, 5432, _) if self.postgres.is_some() => Decoder::Postgres,
            (TCP, _, 5432) if self.postgres.is_some() => Decoder::Postgres,
            _                                         => Decoder::None,
        }
    }

    pub fn decode(&mut self, d: Decoder, flow: &Flow, cs: &mut Customs) -> bool {
        if flow.payload.is_empty() && flow.tcp_flags() & (SYN|FIN) == 0 {
            return false
        }

        match d {
            Decoder::DNS      => self.dns.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::HTTP     => self.http.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::TLS      => self.tls.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::Postgres => self.postgres.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::None     => None,
        }.unwrap_or(false)
    }

    pub fn append(&mut self, d: Decoder, key: &Key, cs: &mut Customs) {
        match d {
            Decoder::TLS => self.tls.as_mut().map(|d| d.append(key, cs)),
            _            => None,
        };
    }

    pub fn clear(&mut self, ts: Timestamp) {
        let timeout = Duration::seconds(15);
        self.dns.as_mut().map(|d| d.clear(ts, timeout));
        self.http.as_mut().map(|d| d.clear(ts, timeout));
        self.tls.as_mut().map(|d| d.clear(ts, timeout));
        //self.postgres.as_mut().map(|d| d.clear(ts, timeout));
    }
}
