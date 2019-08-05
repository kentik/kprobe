#![allow(dead_code)]

use std::collections::HashMap;
use std::ffi::CStr;
use std::net::IpAddr;
use std::ops::Deref;
use time::Duration;
use crate::libkflow::*;
use crate::protocol::Decoder;
use crate::queue::Counter;

pub const FRAGMENTS:              &str = "FRAGMENTS";
pub const APP_LATENCY:            &str = "APPL_LATENCY_MS";
pub const FPX_LATENCY:            &str = "FPEX_LATENCY_MS";
pub const CLIENT_NW_LATENCY:      &str = "CLIENT_NW_LATENCY_MS";
pub const SERVER_NW_LATENCY:      &str = "SERVER_NW_LATENCY_MS";
pub const RETRANSMITTED_IN:       &str = "RETRANSMITTED_IN_PKTS";
pub const RETRANSMITTED_OUT:      &str = "RETRANSMITTED_OUT_PKTS";
pub const REPEATED_RETRANSMITS:   &str = "REPEATED_RETRANSMITS";
pub const OOORDER_IN:             &str = "OOORDER_IN_PKTS";
pub const OOORDER_OUT:            &str = "OOORDER_OUT_PKTS";
pub const RECEIVE_WINDOW:         &str = "RECEIVE_WINDOW";
pub const ZERO_WINDOWS:           &str = "ZERO_WINDOWS";
pub const APP_PROTOCOL:           &str = "APP_PROTOCOL";
pub const CONNECTION_ID:          &str = "CONNECTION_ID";
pub const DNS_QUERY_NAME:         &str = "KFLOW_DNS_QUERY";
pub const DNS_QUERY_TYPE:         &str = "KFLOW_DNS_QUERY_TYPE";
pub const DNS_REPLY_CODE:         &str = "KFLOW_DNS_RET_CODE";
pub const DNS_REPLY_DATA:         &str = "KFLOW_DNS_RESPONSE";
pub const HTTP_URL:               &str = "KFLOW_HTTP_URL";
pub const HTTP_HOST:              &str = "KFLOW_HTTP_HOST";
pub const HTTP_REFERER:           &str = "KFLOW_HTTP_REFERER";
pub const HTTP_UA:                &str = "KFLOW_HTTP_UA";
pub const HTTP_STATUS:            &str = "KFLOW_HTTP_STATUS";
pub const TLS_SERVER_NAME:        &str = "TLS_SERVER_NAME";
pub const TLS_SERVER_VERSION:     &str = "TLS_SERVER_VERSION";
pub const TLS_CIPHER_SUITE:       &str = "TLS_CIPHER_SUITE";
pub const DHCP_OP:                &str = "DHCP_OP";
pub const DHCP_MSG_TYPE:          &str = "DHCP_MSG_TYPE";
pub const DHCP_CI_ADDR:           &str = "DHCP_CI_ADDR";
pub const DHCP_YI_ADDR:           &str = "DHCP_YI_ADDR";
pub const DHCP_SI_ADDR:           &str = "DHCP_SI_ADDR";
pub const DHCP_LEASE:             &str = "DHCP_LEASE";
pub const DHCP_CH_ADDR:           &str = "DHCP_CH_ADDR";
pub const DHCP_HOSTNAME:          &str = "DHCP_HOSTNAME";
pub const DHCP_DOMAIN:            &str = "DHCP_DOMAIN";
pub const RADIUS_CODE:            &str = "RADIUS_CODE";
pub const RADIUS_USER_NAME:       &str = "RADIUS_USER_NAME";
pub const RADIUS_SERVICE_TYPE:    &str = "RADIUS_SERVICE_TYPE";
pub const RADIUS_FRAMED_IP_ADDR:  &str = "RADIUS_FRAMED_IP_ADDR";
pub const RADIUS_FRAMED_IP_MASK:  &str = "RADIUS_FRAMED_IP_MASK";
pub const RADIUS_FRAMED_PROTO:    &str = "RADIUS_FRAMED_PROTO";
pub const RADIUS_ACCT_SESSION_ID: &str = "RADIUS_ACCT_SESSION_ID";
pub const RADIUS_ACCT_STATUS:     &str = "RADIUS_ACCT_STATUS";

#[derive(Debug)]
pub struct Customs {
    app_proto: Option<u64>,
    fragments: Option<u64>,
    fields:    HashMap<String, u64>,
    vec:       Vec<kflowCustom>,
}

impl Customs {
    pub fn new(cs: &[kflowCustom]) -> Self {
        let mut fields = cs.iter().map(|c| {
            (c.name().to_owned(), c.id)
        }).collect::<HashMap<_, _>>();

        if fields.contains_key("APP_PROTOCOL") {
            let str00  = fields["STR00"];
            let str01  = fields["STR01"];
            let str02  = fields["STR02"];
            let str03  = fields["STR03"];
            let int00  = fields["INT00"];
            let int01  = fields["INT01"];
            let int02  = fields["INT02"];
            let addr00 = fields["INET_00"];
            let addr01 = fields["INET_01"];
            let addr02 = fields["INET_02"];
            let ooo    = fields["OOORDER_IN_PKTS"];
            let retx   = fields["RETRANSMITTED_OUT_PKTS"];

            fields.insert(DNS_QUERY_NAME.to_owned(),         str00);
            fields.insert(DNS_QUERY_TYPE.to_owned(),         int00);
            fields.insert(DNS_REPLY_CODE.to_owned(),         int01);
            fields.insert(DNS_REPLY_DATA.to_owned(),         str01);

            fields.insert(HTTP_URL.to_owned(),               str00);
            fields.insert(HTTP_HOST.to_owned(),              str01);
            fields.insert(HTTP_REFERER.to_owned(),           str02);
            fields.insert(HTTP_UA.to_owned(),                str03);
            fields.insert(HTTP_STATUS.to_owned(),            int00);

            fields.insert(TLS_SERVER_NAME.to_owned(),        str00);
            fields.insert(TLS_SERVER_VERSION.to_owned(),     int00);
            fields.insert(TLS_CIPHER_SUITE.to_owned(),       int01);

            fields.insert(DHCP_OP.to_owned(),                int00);
            fields.insert(DHCP_MSG_TYPE.to_owned(),          int01);
            fields.insert(DHCP_CI_ADDR.to_owned(),           addr00);
            fields.insert(DHCP_YI_ADDR.to_owned(),           addr01);
            fields.insert(DHCP_SI_ADDR.to_owned(),           addr02);
            fields.insert(DHCP_LEASE.to_owned(),             int02);
            fields.insert(DHCP_CH_ADDR.to_owned(),           str00);
            fields.insert(DHCP_HOSTNAME.to_owned(),          str01);
            fields.insert(DHCP_DOMAIN.to_owned(),            str02);

            fields.insert(RADIUS_CODE.to_owned(),            int00);
            fields.insert(RADIUS_USER_NAME.to_owned(),       str00);
            fields.insert(RADIUS_SERVICE_TYPE.to_owned(),    int01);
            fields.insert(RADIUS_FRAMED_IP_ADDR.to_owned(),  addr00);
            fields.insert(RADIUS_FRAMED_IP_MASK.to_owned(),  addr01);
            fields.insert(RADIUS_FRAMED_PROTO.to_owned(),    str01);
            fields.insert(RADIUS_ACCT_STATUS.to_owned(),     int02);
            fields.insert(RADIUS_ACCT_SESSION_ID.to_owned(), str02);


            fields.insert(OOORDER_IN.to_owned(),             ooo);
            fields.insert(OOORDER_OUT.to_owned(),            ooo);
            fields.insert(RETRANSMITTED_IN.to_owned(),       retx);
            fields.insert(RETRANSMITTED_OUT.to_owned(),      retx);
        } else if let Some(id) = fields.get(HTTP_HOST).cloned() {
            fields.insert(TLS_SERVER_NAME.to_owned(), id);
        }

        Customs{
            app_proto: fields.get(APP_PROTOCOL).cloned(),
            fragments: fields.get(FRAGMENTS).cloned(),
            fields:    fields,
            vec:       Vec::with_capacity(cs.len()),
        }
    }

    pub fn append(&mut self, ctr: &Counter) {
        if ctr.fragments > 0 {
            self.fragments.map(|id| self.add_u32(id, ctr.fragments as u32));
        }

        self.app_proto.map(|id| {
            match ctr.decoder {
                Decoder::DNS    => self.add_u32(id, 1),
                Decoder::HTTP   => self.add_u32(id, 2),
                Decoder::TLS    => self.add_u32(id, 3),
                Decoder::DHCP   => self.add_u32(id, 4),
                Decoder::Radius => self.add_u32(id, 9),
                _               => (),
            }
        });
    }

    pub fn add_str(&mut self, id: u64, val: &CStr) {
        self.vec.push(kflowCustom::str(id, val))
    }

    pub fn add_u32(&mut self, id: u64, val: u32) {
        self.vec.push(kflowCustom::u32(id, val))
    }

    pub fn add_addr(&mut self, id: u64, val: IpAddr) {
        self.vec.push(kflowCustom::addr(id, val))
    }

    pub fn add_latency(&mut self, id: u64, d: Duration) {
        let max = Duration::seconds(20);
        let min = Duration::milliseconds(1);
        self.add_u32(id, match d {
            d if d >= min && d <= max => d,
            d if d >= min             => max,
            _                         => min,
        }.num_milliseconds() as u32);
    }

    pub fn clear(&mut self) {
        self.vec.clear();
    }

    pub fn get(&self, key: &str) -> Result<u64, ()> {
        match self.fields.get(key) {
            Some(id) => Ok(*id),
            None     => Err(()),
        }
    }
}

impl Deref for Customs {
    type Target = [kflowCustom];
    fn deref(&self) -> &[kflowCustom] {
        &self.vec[..]
    }
}
