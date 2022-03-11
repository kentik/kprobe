use std::fmt;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::ptr::addr_of_mut;
use pnet::packet::tcp::TcpPacket;
use pnet::util::MacAddr;
use crate::time::Timestamp;

pub const FIN: u16 = 0b00001;
pub const SYN: u16 = 0b00010;
pub const RST: u16 = 0b00100;
pub const ACK: u16 = 0b10000;

#[derive(Clone)]
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
    pub direction: Direction,
    pub export:    bool,
    pub payload:   &'a [u8]
}

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

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub struct Addr {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Copy, Clone, Debug)]
pub enum Transport {
    ICMP,
    TCP  { seq: u32, flags: u16, window: Window },
    UDP,
    Other,
}

#[derive(Copy, Clone, Debug)]
pub struct Window {
    pub size:  u32,
    pub scale: u8,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Key(pub Protocol, pub Addr, pub Addr);

#[derive(Copy, Clone, Debug)]
pub enum Direction {
    In, Out, Unknown
}

impl<'a> Flow<'a> {
    pub fn key(&self) -> Key {
        Key(self.protocol, self.src, self.dst)
    }

    pub fn tcp_flags(&self) -> u16 {
        match self.transport {
            Transport::TCP { flags, .. } => flags,
            _                            => 0,
        }
    }
}

impl<'a> Default for Flow<'a> {
    fn default() -> Self {
        unsafe {
            let mut flow: MaybeUninit<Flow> = MaybeUninit::zeroed();
            addr_of_mut!((*flow.as_mut_ptr()).payload).write(&[]);
            flow.assume_init()
        }
    }
}

impl Default for Window {
    fn default() -> Self {
        Window{
            size:  0,
            scale: 0,
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

pub fn tcp_window(p: &TcpPacket) -> Window {
    let mut scale = 1u8;

    if p.get_flags() & SYN == SYN {
        use pnet::packet::Packet;
        use pnet::packet::tcp::TcpOptionNumbers::WSCALE;

        for o in p.get_options_iter().filter(|o| o.get_number() == WSCALE) {
            if let &[n] = o.payload() {
                scale = n;
            }
        }
    }

    Window {
        size:  p.get_window() as u32,
        scale: scale,
    }
}
