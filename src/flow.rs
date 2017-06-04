use std::fmt;
use std::mem;
use std::net::IpAddr;
use std::ops::Sub;
use std::ptr;
use libc::{self, timeval};
use pnet::util::MacAddr;
use time::{self, Duration};

pub struct Flow<'a> {
    pub timestamp: Timestamp,
    pub ethernet:  Ethernet,
    pub protocol:  Protocol,
    pub src:       Addr,
    pub dst:       Addr,
    pub tos:       u8,
    pub transport: Transport,
    pub packets:   u16,
    pub fragments: u16,
    pub bytes:     usize,
    pub payload:   &'a [u8]
}

#[derive(Copy, Clone)]
pub struct Timestamp(pub timeval);

#[derive(Copy, Clone, Debug)]
pub struct Ethernet {
    pub src:  MacAddr,
    pub dst:  MacAddr,
    pub vlan: Option<u16>
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    ICMP,
    TCP,
    UDP,
    Other(u16),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Addr {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Copy, Clone, Debug)]
pub enum Transport {
    ICMP,
    TCP  { flags: u16 },
    UDP,
    Other,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Key(pub Protocol, pub Addr, pub Addr);

#[derive(Debug)]
pub enum Direction {
    In, Out, Unknown
}

impl<'a> Flow<'a> {
    pub fn key(&self) -> Key {
        Key(self.protocol, self.src, self.dst)
    }
}

impl Timestamp {
    pub fn now() -> Self {
        Timestamp(unsafe {
            let tv: timeval = mem::zeroed();
            let tvp = &tv as *const timeval as *mut timeval;
            libc::gettimeofday(tvp, ptr::null_mut());
            tv
        })
    }

    pub fn zero() -> Self {
        Timestamp(timeval{
            tv_sec:  0,
            tv_usec: 0,
        })
    }
}

impl Sub for Timestamp {
    type Output = Duration;

    fn sub(self, rhs: Timestamp) -> Self::Output {
        let sec = self.0.tv_sec - rhs.0.tv_sec;
        let usec = self.0.tv_usec - rhs.0.tv_usec;
        Duration::seconds(sec) + Duration::microseconds(usec as i64)
    }
}

impl<'a> Default for Flow<'a> {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tm = time::at(time::Timespec{
            sec:  self.0.tv_sec,
            nsec: self.0.tv_usec as i32 * 1000,
        });

        match time::strftime("%F %T", &tm) {
            Ok(str) => write!(f, "{}", str),
            Err(..) => Err(fmt::Error)
        }
    }
}

impl<'a> fmt::Debug for Flow<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Flow")
            .field("ethernet", &self.ethernet)
            .field("protocol", &self.protocol)
            .field("src", &self.src)
            .field("dst", &self.dst)
            .finish()
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Timestamp")
            .field("tv_sec", &self.0.tv_sec)
            .field("tv_usec", &self.0.tv_usec)
            .finish()
    }
}
