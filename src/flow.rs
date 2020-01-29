use std::cmp::Ordering;
use std::fmt;
use std::mem::{self, MaybeUninit};
use std::net::IpAddr;
use std::ops::{Add, Sub};
use std::ptr;
use libc::{self, timeval};
use pnet::packet::tcp::TcpPacket;
use pnet::util::MacAddr;
use time::{self, Duration};

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

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Duration) -> Self::Output {
        Timestamp(timeval{
            tv_sec:  self.0.tv_sec + rhs.num_seconds(),
            tv_usec: self.0.tv_usec,
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

impl PartialEq for Timestamp {
    fn eq(&self, other: &Timestamp) -> bool {
        let &Timestamp(timeval{tv_sec: a_sec, tv_usec: a_usec}) = self;
        let &Timestamp(timeval{tv_sec: b_sec, tv_usec: b_usec}) = other;
        a_sec == b_sec && a_usec == b_usec
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Timestamp) -> Option<Ordering> {
        let &Timestamp(timeval{tv_sec: a_sec, tv_usec: a_usec}) = self;
        let &Timestamp(timeval{tv_sec: b_sec, tv_usec: b_usec}) = other;
        match a_sec - b_sec {
            n if n == 0 => Some(a_usec.cmp(&b_usec)),
            n if n >  0 => Some(Ordering::Greater),
            _           => Some(Ordering::Less),
        }
    }
}

impl<'a> Default for Flow<'a> {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
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
