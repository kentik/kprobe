#![allow(dead_code)]

use std::collections::HashMap;
use std::ffi::CStr;
use std::ops::Deref;
use std::ptr;
use time::Duration;
use libkflow::*;
use queue::Counter;

pub const FRAGMENTS:            &str = "FRAGMENTS";
pub const APP_LATENCY:          &str = "APPL_LATENCY_MS";
pub const FPX_LATENCY:          &str = "FPEX_LATENCY_MS";
pub const CLIENT_NW_LATENCY:    &str = "CLIENT_NW_LATENCY_MS";
pub const SERVER_NW_LATENCY:    &str = "SERVER_NW_LATENCY_MS";
pub const RETRANSMITTED_IN:     &str = "RETRANSMITTED_IN_PKTS";
pub const RETRANSMITTED_OUT:    &str = "RETRANSMITTED_OUT_PKTS";
pub const REPEATED_RETRANSMITS: &str = "REPEATED_RETRANSMITS";
pub const OOORDER_IN:           &str = "OOORDER_IN_PKTS";
pub const OOORDER_OUT:          &str = "OOORDER_OUT_PKTS";
pub const RECEIVE_WINDOW:       &str = "RECEIVE_WINDOW";
pub const ZERO_WINDOWS:         &str = "ZERO_WINDOWS";
pub const APP_PROTOCOL:         &str = "APP_PROTOCOL";
pub const CONNECTION_ID:        &str = "CONNECTION_ID";
pub const DNS_QUERY_NAME:       &str = "KFLOW_DNS_QUERY";
pub const DNS_QUERY_TYPE:       &str = "KFLOW_DNS_QUERY_TYPE";
pub const DNS_REPLY_CODE:       &str = "KFLOW_DNS_RET_CODE";
pub const DNS_REPLY_DATA:       &str = "KFLOW_DNS_RESPONSE";
pub const HTTP_URL:             &str = "KFLOW_HTTP_URL";
pub const HTTP_HOST:            &str = "KFLOW_HTTP_HOST";
pub const HTTP_REFERER:         &str = "KFLOW_HTTP_REFERER";
pub const HTTP_UA:              &str = "KFLOW_HTTP_UA";
pub const HTTP_STATUS:          &str = "KFLOW_HTTP_STATUS";
pub const TLS_SERVER_NAME:      &str = "KFLOW_HTTP_HOST";

#[derive(Debug)]
pub struct Customs {
    fragments: Option<u64>,
    fields:    HashMap<String, u64>,
    vec:       Vec<kflowCustom>,
}

impl Customs {
    pub fn new(cs: &[kflowCustom]) -> Self {
        let fields = cs.iter().map(|c| {
            (c.name().to_owned(), c.id)
        }).collect::<HashMap<_, _>>();

        Customs{
            fragments: fields.get(FRAGMENTS).cloned(),
            fields:    fields,
            vec:       Vec::with_capacity(cs.len()),
        }
    }

    pub fn append(&mut self, ctr: &Counter) {
        if ctr.fragments > 0 {
            self.fragments.map(|id| self.add_u32(id, ctr.fragments as u32));
        }
    }

    pub fn add_str(&mut self, id: u64, val: &CStr) {
        self.vec.place_back() <- kflowCustom{
            name:  ptr::null(),
            id:    id,
            vtype: KFLOW_CUSTOM_STR,
            value: kflowCustomValue{
                str: val.as_ptr(),
            },
        };
    }

    pub fn add_u32(&mut self, id: u64, val: u32) {
        self.vec.place_back() <- kflowCustom{
            name:  ptr::null(),
            id:    id,
            vtype: KFLOW_CUSTOM_U32,
            value: kflowCustomValue{
                u32: val,
            },
        };
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
