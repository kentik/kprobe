use time::Duration;
use crate::flow::{Flow, Key};
use crate::flow::{FIN, SYN};
use crate::flow::Protocol::{TCP, UDP};
use crate::custom::Customs;
use crate::protocol::*;
use crate::protocol::dhcp;
use crate::time::Timestamp;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Decoder {
    DHCP, DNS, HTTP, Postgres, Radius, TLS, None
}

#[derive(Default)]
pub struct Decoders {
    dns:      Option<dns::Decoder>,
    dhcp:     Option<dhcp::Decoder>,
    http:     Option<http::Decoder>,
    tls:      Option<tls::Decoder>,
    postgres: Option<postgres::Decoder>,
    radius:   Option<radius::Decoder>,
}

impl Decoders {
    pub fn new(cs: &Customs, classify: &mut Classify, decode: bool) -> Self {
        let mut decoders = Self::default();

        if decode {
            if let Ok(d) = dns::Decoder::new(cs) {
                // Populated in bin/kprobe.rs
                decoders.dns = Some(d);
            }

            if let Ok(d) = dhcp::Decoder::new(cs) {
                classify.add(UDP, 67, Decoder::DHCP);
                classify.add(UDP, 68, Decoder::DHCP);
                decoders.dhcp = Some(d);
            }

            if let Ok(d) = http::Decoder::new(cs) {
                classify.add(TCP, 80, Decoder::HTTP);
                decoders.http = Some(d);
            }

            if let Ok(d) = tls::Decoder::new(cs) {
                classify.add(TCP, 443, Decoder::TLS);
                decoders.tls = Some(d);
            }

            if let Ok(d) = radius::Decoder::new(cs) {
                // Populated in bin/kprobe.rs
                decoders.radius = Some(d);
            }
        }

        decoders
    }

    pub fn decode(&mut self, d: Decoder, flow: &Flow, cs: &mut Customs) -> bool {
        if flow.payload.is_empty() && flow.tcp_flags() & (SYN|FIN) == 0 {
            return false
        }

        match d {
            Decoder::DHCP     => self.dhcp.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::DNS      => self.dns.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::HTTP     => self.http.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::TLS      => self.tls.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::Postgres => self.postgres.as_mut().map(|d| d.decode(flow, cs)),
            Decoder::Radius   => self.radius.as_mut().map(|d| d.decode(flow, cs)),
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
        self.dhcp.as_mut().map(|d| d.clear(ts, timeout));
        self.dns.as_mut().map(|d| d.clear(ts, timeout));
        self.http.as_mut().map(|d| d.clear(ts, timeout));
        self.tls.as_mut().map(|d| d.clear(ts, timeout));
        self.radius.as_mut().map(|d| d.clear(ts, timeout));
        //self.postgres.as_mut().map(|d| d.clear(ts, timeout));
    }
}
