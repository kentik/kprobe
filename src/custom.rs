#![allow(dead_code)]

use std::collections::HashMap;
use std::ffi::CStr;
use std::ops::Deref;
use std::ptr;
use time::Duration;
use libkflow::*;
use queue::Counter;

const KFLOW_FRAGMENTS: &str = "FRAGMENTS";

#[derive(Debug)]
pub struct Customs {
    fragments: Option<u64>,
    vec:       Vec<kflowCustom>,
}

impl Customs {
    pub fn new(cs: &[kflowCustom]) -> Self {
        let cs = cs.iter().map(|c| {
            (c.name(), c.id)
        }).collect::<HashMap<_, _>>();

        Customs{
            fragments: cs.get(KFLOW_FRAGMENTS).cloned(),
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
}

impl Deref for Customs {
    type Target = [kflowCustom];
    fn deref(&self) -> &[kflowCustom] {
        &self.vec[..]
    }
}
