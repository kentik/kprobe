use std::io::Error;
use std::os::unix::io::RawFd;

#[cfg(target_os = "linux")]
pub fn random(fd: RawFd, n: u32) -> Result<(), Error> {
    use bpf::{self, Op, Prog};

    bpf::attach_filter(fd, Prog::new(vec![
        Op::new(0x20, 0, 0, 0xfffff038),
        Op::new(0x94, 0, 0, n),
        Op::new(0x15, 0, 1, 0x00000001),
        Op::new(0x06, 0, 0, 0xffffffff),
        Op::new(0x06, 0, 0, 0000000000),
    ]))
}

#[cfg(not(target_os = "linux"))]
pub fn random(_fd: RawFd, _n: u32) -> Result<(), Error> {
    unimplemented!();
}
