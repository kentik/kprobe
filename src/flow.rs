use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug)]
pub struct Flow {
    pub timestamp: SystemTime,
    pub protocol:  Protocol,
    pub src:       Addr,
    pub dst:       Addr,
    pub packets:   usize,
    pub bytes:     usize,
    pub payload:   Option<Vec<Payload>>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Addr {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Debug)]
pub enum Payload {
    Postgres(Postgres),
}

#[derive(Debug)]
pub enum Postgres {
    Query(String),
    QueryComplete,
}
