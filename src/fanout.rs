use log::info;
use pcap::{Capture, Active};
use crate::args::{Error, FromArg};

const PACKET_FANOUT_HASH: u32 = 0x0;
const PACKET_FANOUT_LB:   u32 = 0x1;

#[derive(Debug)]
#[repr(u32)]
pub enum Mode {
    Hash = PACKET_FANOUT_HASH,
    LB   = PACKET_FANOUT_LB,
}

#[cfg(target_os = "linux")]
pub fn join(cap: &Capture<Active>, group: u16, mode: Mode) -> Result<(), Error> {
    use std::mem::size_of;
    use std::os::unix::io::AsRawFd;
    use libc::{c_int, c_void};
    use errno::errno;

    const SOL_PACKET:    c_int = 263;
    const PACKET_FANOUT: c_int = 0x12;

    let mode  = mode  as c_int;
    let group = group as c_int;
    let val   = mode << 16 | group;

    unsafe {
        let fd  = cap.as_raw_fd() as c_int;
        let val = &val as *const _ as *const c_void;
        let len = size_of::<c_int>() as u32;

        match libc::setsockopt(fd, SOL_PACKET, PACKET_FANOUT, val, len) {
            0 => Ok(info!("joined fanout group {}, mode {}", group, mode)),
            _ => Err(errno().into()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn join(_cap: &Capture<Active>, _group: u16, _mode: Mode) -> Result<(), Error> {
    unimplemented!();
}

impl FromArg for Mode {
    fn from_arg(mode: &str) -> Result<Self, Error> {
        match mode {
            "hash" => Ok(Mode::Hash),
            "lb"   => Ok(Mode::LB),
            other  => Err(Error::Invalid(format!("invalid fanout mode: {}", other))),
        }
    }
}
