use std::ffi::CStr;
use std::ops::Deref;
use std::ptr;
use libkflow::*;

pub struct Customs {
    vec: Vec<kflowCustom>,
}

impl Customs {
    pub fn new(cap: usize) -> Self {
        Customs{
            vec: Vec::with_capacity(cap),
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
