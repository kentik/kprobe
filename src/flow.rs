use std::net::IpAddr;
use std::time::SystemTime;
use pnet::util::MacAddr;

#[derive(Debug)]
pub struct Flow<'a> {
    pub timestamp: SystemTime,
    pub ethernet:  Ethernet,
    pub protocol:  Protocol,
    pub src:       Addr,
    pub dst:       Addr,
    pub tos:       u8,
    pub transport: Transport,
    pub bytes:     usize,
    pub payload:   &'a [u8]
}

#[derive(Copy, Clone, Debug)]
pub struct Ethernet {
    pub src: MacAddr,
    pub dst: MacAddr,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    ICMP,
    TCP,
    UDP,
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
}
