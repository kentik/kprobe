use std::fmt;
use std::net::IpAddr;
use libc::timeval;
use pnet::util::MacAddr;
use time::Timespec;

pub struct Flow<'a> {
    pub timestamp: Timestamp,
    pub ethernet:  Ethernet,
    pub protocol:  Protocol,
    pub src:       Addr,
    pub dst:       Addr,
    pub tos:       u8,
    pub transport: Transport,
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
    pub fn zero() -> Self {
        Timestamp(timeval{
            tv_sec:  0,
            tv_usec: 0,
        })
    }

    pub fn timespec(&self) -> Timespec {
        Timespec{
            sec:  self.0.tv_sec as i64,
            nsec: (self.0.tv_usec * 1000) as i32,
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
