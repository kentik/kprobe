use time::Duration;
use flow::{Flow, Key, Timestamp};
use flow::{FIN, SYN};
use flow::Protocol::{TCP, UDP};
use custom::Customs;
use protocol::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
    pub fn new(cs: &Customs, classify: &mut Classify, decode: bool) -> Self {
        let mut decoders = Self::default();

        if decode {
            if let Ok(d) = dns::Decoder::new(cs) {
                classify.add(UDP, 53, Decoder::DNS);
                decoders.dns = Some(d);
            }

            if let Ok(d) = http::Decoder::new(cs) {
                classify.add(TCP, 80, Decoder::HTTP);
                decoders.http = Some(d);
            }

            if let Ok(d) = tls::Decoder::new(cs) {
                classify.add(TCP, 443, Decoder::TLS);
                decoders.tls = Some(d);
            }
        }

        decoders
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
        let timeout = Duration::seconds(60);
        self.dns.as_mut().map(|d| d.clear(ts, timeout));
        self.http.as_mut().map(|d| d.clear(ts, timeout));
        self.tls.as_mut().map(|d| d.clear(ts, timeout));
        //self.postgres.as_mut().map(|d| d.clear(ts, timeout));
    }
}
