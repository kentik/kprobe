use pcap::{Capture, Active};
use args::Error;

#[cfg(target_os = "linux")]
pub fn join(cap: &Capture<Active>, group: u16) -> Result<(), Error> {
    use std::mem;
    use std::os::unix::io::AsRawFd;
    use libc::{self, c_int, c_void};
    use errno::errno;

    const SOL_PACKET:         c_int = 263;
    const PACKET_FANOUT:      c_int = 0x12;
    const PACKET_FANOUT_HASH: c_int = 0x0;

    let fd  = cap.as_raw_fd() as c_int;
    let val = PACKET_FANOUT_HASH << 16 | (group as c_int);

    unsafe {
        let val = &val as *const _ as *const c_void;
        let len = mem::size_of::<c_int>() as u32;

        match libc::setsockopt(fd, SOL_PACKET, PACKET_FANOUT, val, len) {
            0 => Ok(()),
            _ => Err(errno().into()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn join(_cap: &Capture<Active>, _group: u16) -> Result<(), Error> {
    unimplemented!();
}
