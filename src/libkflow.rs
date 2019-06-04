#![allow(non_snake_case, unused)]

use std::convert::TryInto;
use std::default::Default;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::net::IpAddr;
use std::{fmt, ptr, slice};
use pnet::datalink::NetworkInterface;
use pnet::util::MacAddr;
use pnet::packet::PrimitiveValues;
use time::Duration;
use libc::{self, c_char, c_int};
use super::flow::{Direction, Key, Protocol};
use super::queue::Counter;

#[derive(Debug)]
pub struct Config {
    pub url:         CString,
    pub api:         API,
    pub capture:     Capture,
    pub metrics:     Metrics,
    pub proxy:       Option<CString>,
    pub status:      Status,
    pub dns:         DNS,
    pub device_id:   u32,
    pub device_if:   Option<CString>,
    pub device_ip:   Option<CString>,
    pub device_name: CString,
    pub device_plan: Option<u32>,
    pub device_site: Option<u32>,
    pub sample:      u32,
    pub timeout:     Duration,
    pub verbose:     u32,
    pub program:     CString,
    pub version:     CString,
}

#[derive(Debug)]
pub struct API {
    pub email: CString,
    pub token: CString,
    pub url:   CString,
}

#[derive(Debug)]
pub struct Capture {
    pub device:  CString,
    pub snaplen: i32,
    pub promisc: bool,
    pub ip:      Option<CString>,
}

#[derive(Debug)]
pub struct Metrics {
    pub interval: Duration,
    pub url:      CString,
}

#[derive(Debug)]
pub struct Status {
    pub host: CString,
    pub port: u16,
}

#[derive(Debug)]
pub struct DNS {
    pub enable:   bool,
    pub interval: Duration,
    pub url:      CString,
}

#[derive(Debug)]
pub struct Device {
    pub id:      u64,
    pub name:    CString,
    pub sample:  u64,
    pub customs: Vec<kflowCustom>,
}

#[derive(Debug)]
pub enum Error {
    InvalidString(Vec<u8>),
    InvalidConfig,
    Timeout,
    Failed(u32),
}

impl Config {
    pub fn new(dev: &NetworkInterface, region: Option<String>, snaplen: i32, promisc: bool) -> Self {
        let program = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");

        let device  = dev.name.clone();
        let ip      = dev.ips.iter().filter(|net| net.ip().is_ipv4()).map(|net| {
            CString::new(net.ip().to_string()).unwrap()
        }).next();

        let region = region.as_ref().map(String::as_str).unwrap_or("US");
        let domain = match region.to_ascii_uppercase().as_ref() {
            "US" => "kentik.com".to_owned(),
            "EU" => "kentik.eu".to_owned(),
            name => format!("{}.kentik.com", name.to_ascii_lowercase()),
        };

        let api  = CString::new(format!("https://api.{}/api/internal", domain)).unwrap();
        let flow = CString::new(format!("https://flow.{}/chf", domain)).unwrap();
        let tsdb = CString::new(format!("https://flow.{}/tsdb", domain)).unwrap();
        let dns  = CString::new(format!("https://flow.{}/dns", domain)).unwrap();

        Config {
            url: flow,
            api: API{
                email: CString::new("test@example.com").unwrap(),
                token: CString::new("token").unwrap(),
                url:   api,
            },
            capture: Capture{
                device:  CString::new(device).unwrap(),
                snaplen: snaplen,
                promisc: promisc,
                ip:      ip,
            },
            metrics: Metrics{
                interval: Duration::minutes(1),
                url:      tsdb,
            },
            proxy:   None,
            status:  Status{
                host: CString::new("127.0.0.1").unwrap(),
                port: 0,
            },
            dns: DNS{
                enable:   false,
                interval: Duration::seconds(1),
                url:      dns,
            },
            device_id:   0,
            device_if:   None,
            device_ip:   None,
            device_name: hostname(),
            device_plan: None,
            device_site: None,
            sample:      0,
            timeout:     Duration::seconds(30),
            verbose:     0,
            program:     CString::new(program).unwrap(),
            version:     CString::new(version).unwrap(),
        }
    }
}

pub fn configure(cfg: &Config) -> Result<Device, Error> {
    fn opt(cstr: &Option<CString>) -> *const c_char {
        cstr.as_ref().map(|s| s.as_ptr()).unwrap_or(ptr::null())
    }

    let c_cfg = kflowConfig {
        URL: cfg.url.as_ptr(),
        API: kflowConfigAPI {
            email: cfg.api.email.as_ptr(),
            token: cfg.api.token.as_ptr(),
            URL:   cfg.api.url.as_ptr(),

        },
        capture: kflowConfigCapture {
            device:  cfg.capture.device.as_ptr(),
            snaplen: cfg.capture.snaplen,
            promisc: cfg.capture.promisc as c_int,
            ip:      opt(&cfg.capture.ip),
        },
        metrics: kflowConfigMetrics {
            interval: cfg.metrics.interval.num_minutes() as c_int,
            URL:      cfg.metrics.url.as_ptr(),
        },
        proxy: kflowConfigProxy {
            URL: opt(&cfg.proxy),
        },
        status: kflowConfigStatus {
            host: cfg.status.host.as_ptr(),
            port: cfg.status.port as c_int,
        },
        dns: kflowConfigDNS {
            enable:   cfg.dns.enable as c_int,
            interval: cfg.dns.interval.num_seconds() as c_int,
            URL:      cfg.dns.url.as_ptr(),
        },
        device_id:   cfg.device_id as c_int,
        device_if:   opt(&cfg.device_if),
        device_ip:   opt(&cfg.device_ip),
        device_name: cfg.device_name.as_ptr(),
        device_plan: cfg.device_plan.unwrap_or(0) as c_int,
        device_site: cfg.device_site.unwrap_or(0) as c_int,
        sample:      cfg.sample as c_int,
        timeout:     cfg.timeout.num_milliseconds() as c_int,
        verbose:     cfg.verbose as c_int,
        program:     cfg.program.as_ptr(),
        version:     cfg.version.as_ptr(),
    };

    let mut dev = kflowDevice {
        id:          0,
        name:        ptr::null(),
        sample_rate: 0,
        c_customs:   ptr::null(),
        n_customs:   0,
    };

    unsafe fn device(dev: &kflowDevice) -> Device {
        let ptr = dev.c_customs;
        let len = dev.n_customs as usize;
        Device {
            id:      dev.id,
            name:    CStr::from_ptr(dev.name).to_owned(),
            sample:  dev.sample_rate,
            customs: slice::from_raw_parts(ptr, len).to_vec(),
        }
    };

    unsafe {
        match kflowInit(&c_cfg, &mut dev) {
            0 => Ok(device(&dev)),
            1 => Err(Error::InvalidConfig),
            n => Err(Error::Failed(n as u32))
        }
    }
}

pub fn send(key: &Key, ctr: &Counter, sr: u32, cs: Option<&[kflowCustom]>) -> Result<(), Error> {
    let mut kflow: kflow = Default::default();
    let mut v6src: [u8; 16];
    let mut v6dst: [u8; 16];

    match key.0 {
        Protocol::ICMP     => kflow.protocol = 1,
        Protocol::TCP      => kflow.protocol = 6,
        Protocol::UDP      => kflow.protocol = 17,
        Protocol::Other(n) => kflow.protocol = n as u32,
    };

    match key.1.addr {
        IpAddr::V4(ip) => {
            kflow.ipv4SrcAddr = ip.into();
        },
        IpAddr::V6(ip) => {
            v6src = ip.octets();
            kflow.ipv6SrcAddr = v6src.as_ptr() as *const u8;
        },
    }

    match key.2.addr {
        IpAddr::V4(ip) => {
            kflow.ipv4DstAddr = ip.into();
        },
        IpAddr::V6(ip) => {
            v6dst = ip.octets();
            kflow.ipv6DstAddr = v6dst.as_ptr() as *const u8;

        },
    }

    kflow.srcEthMac  = pack_mac(&ctr.ethernet.src);
    kflow.dstEthMac  = pack_mac(&ctr.ethernet.dst);
    kflow.tos        = ctr.tos as u32;
    kflow.l4SrcPort  = key.1.port as u32;
    kflow.l4DstPort  = key.2.port as u32;
    kflow.tcpFlags   = ctr.tcp_flags as u32;
    kflow.sampleRate = sr;

    match ctr.direction {
        Direction::In => {
            kflow.inPkts     = ctr.packets;
            kflow.inBytes    = ctr.bytes;
            kflow.inputPort  = (kflow.dstEthMac & 0xFFFF) as u32;
            kflow.vlanIn     = ctr.ethernet.vlan.unwrap_or(0) as u32;
        },
        Direction::Out | Direction::Unknown => {
            kflow.outPkts    = ctr.packets;
            kflow.outBytes   = ctr.bytes;
            kflow.outputPort = (kflow.srcEthMac & 0xFFFF) as u32;
            kflow.vlanOut    = ctr.ethernet.vlan.unwrap_or(0) as u32;
        },
    }

    if let Some(cs) = cs {
        kflow.customs    = cs.as_ptr();
        kflow.numCustoms = cs.len() as u32;
    }

    unsafe {
        match kflowSend(&kflow) {
            0 => Ok(()),
            n => Err(Error::Failed(n as u32)),
        }
    }
}

pub fn stop(timeout: Duration) -> Result<(), Error> {
    unsafe {
        match kflowStop(timeout.num_milliseconds() as c_int) {
            0 => Ok(()),
            _ => Err(Error::Timeout),
        }
    }
}

pub fn error() -> Option<String> {
    unsafe {
        let cstr = kflowError();
        if cstr.is_null() {
            return None;
        }

        let err = CStr::from_ptr(cstr).to_owned();
        libc::free(cstr as *mut libc::c_void);
        Some(err.into_string().unwrap())
    }
}

pub fn version() -> String {
    unsafe {
        let cstr = kflowVersion();
        let ver = CStr::from_ptr(cstr).to_owned();
        libc::free(cstr as *mut libc::c_void);
        ver.into_string().unwrap()
    }
}

pub fn hostname() -> CString {
    unsafe {
        let mut bytes = [0u8; 64];

        let ptr = bytes.as_mut_ptr() as *mut c_char;
        let len = bytes.len();
        libc::gethostname(ptr, len);

        CStr::from_ptr(ptr).to_owned()
    }
}

#[link(name = "kflow")]
extern {
    fn kflowInit(cfg: *const kflowConfig, dev: *mut kflowDevice) -> c_int;
    fn kflowSend(flow: *const kflow) -> c_int;
    fn kflowStop(timeout: c_int) -> c_int;
    fn kflowError() -> *const c_char;
    fn kflowVersion() -> *const c_char;
    fn kflowSendDNS(q: kflowDomainQuery, a: *const kflowDomainAnswer, n: usize) -> c_int;
    fn kflowSendEncodedDNS(ptr: *const u8, len: usize) -> c_int;
}

pub const KFLOW_CUSTOM_STR:  c_int =  1;
pub const KFLOW_CUSTOM_U8:   c_int =  2;
pub const KFLOW_CUSTOM_U16:  c_int =  3;
pub const KFLOW_CUSTOM_U32:  c_int =  4;
pub const KFLOW_CUSTOM_U64:  c_int =  5;
pub const KFLOW_CUSTOM_I8:   c_int =  6;
pub const KFLOW_CUSTOM_I16:  c_int =  7;
pub const KFLOW_CUSTOM_I32:  c_int =  8;
pub const KFLOW_CUSTOM_I64:  c_int =  9;
pub const KFLOW_CUSTOM_F32:  c_int = 10;
pub const KFLOW_CUSTOM_F64:  c_int = 11;
pub const KFLOW_CUSTOM_ADDR: c_int = 12;

#[repr(C)]
struct kflowConfig {
    URL:         *const c_char,
    API:         kflowConfigAPI,
    capture:     kflowConfigCapture,
    metrics:     kflowConfigMetrics,
    proxy:       kflowConfigProxy,
    status:      kflowConfigStatus,
    dns:         kflowConfigDNS,
    device_id:   c_int,
    device_if:   *const c_char,
    device_ip:   *const c_char,
    device_name: *const c_char,
    device_plan: c_int,
    device_site: c_int,
    sample:      c_int,
    timeout:     c_int,
    verbose:     c_int,
    program:     *const c_char,
    version:     *const c_char,
}

#[repr(C)]
struct kflowConfigAPI {
    email: *const c_char,
    token: *const c_char,
    URL:   *const c_char,
}

#[repr(C)]
struct kflowConfigCapture {
    device:  *const c_char,
    snaplen: c_int,
    promisc: c_int,
    ip:      *const c_char,
}

#[repr(C)]
struct kflowConfigMetrics {
    interval: c_int,
    URL:      *const c_char,
}

#[repr(C)]
struct kflowConfigProxy {
    URL: *const c_char,
}

#[repr(C)]
struct kflowConfigStatus {
    host: *const c_char,
    port: c_int,
}

#[repr(C)]
struct kflowConfigDNS {
    enable:   c_int,
    interval: c_int,
    URL:      *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct kflowCustom {
    pub name:  *const c_char,
    pub id:    u64,
    pub vtype: c_int,
    pub value: kflowCustomValue,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union kflowCustomValue {
    pub str:  *const c_char,
    pub u8:   u8,
    pub u16:  u16,
    pub u32:  u32,
    pub u64:  u64,
    pub i8:   i8,
    pub i16:  i16,
    pub i32:  i32,
    pub i64:  i64,
    pub f32:  f32,
    pub f64:  f64,
    pub addr: [u8; 17],
}

#[repr(C)]
pub struct kflowDevice {
    pub id:          u64,
    pub name:        *const c_char,
    pub sample_rate: u64,
    pub c_customs:   *const kflowCustom,
    pub n_customs:   u32,
}

#[repr(C)]
pub struct kflow {
    pub timestampNano: i64,
    pub dstAs: u32,
    pub dstGeo: u32,
    pub dstMac: u32,
    pub headerLen: u32,
    pub inBytes: u64,
    pub inPkts: u64,
    pub inputPort: u32,
    pub ipSize: u32,
    pub ipv4DstAddr: u32,
    pub ipv4SrcAddr: u32,
    pub l4DstPort: u32,
    pub l4SrcPort: u32,
    pub outputPort: u32,
    pub protocol: u32,
    pub sampledPacketSize: u32,
    pub srcAs: u32,
    pub srcGeo: u32,
    pub srcMac: u32,
    pub tcpFlags: u32,
    pub tos: u32,
    pub vlanIn: u32,
    pub vlanOut: u32,
    pub ipv4NextHop: u32,
    pub mplsType: u32,
    pub outBytes: u64,
    pub outPkts: u64,
    pub tcpRetransmit: u32,
    pub srcFlowTags: *mut ::std::os::raw::c_char,
    pub dstFlowTags: *mut ::std::os::raw::c_char,
    pub sampleRate: u32,
    pub deviceId: u32,
    pub flowTags: *mut ::std::os::raw::c_char,
    pub timestamp: i64,
    pub dstBgpAsPath: *mut ::std::os::raw::c_char,
    pub dstBgpCommunity: *mut ::std::os::raw::c_char,
    pub srcBgpAsPath: *mut ::std::os::raw::c_char,
    pub srcBgpCommunity: *mut ::std::os::raw::c_char,
    pub srcNextHopAs: u32,
    pub dstNextHopAs: u32,
    pub srcGeoRegion: u32,
    pub dstGeoRegion: u32,
    pub srcGeoCity: u32,
    pub dstGeoCity: u32,
    pub big: u8,
    pub sampleAdj: u8,
    pub ipv4DstNextHop: u32,
    pub ipv4SrcNextHop: u32,
    pub srcRoutePrefix: u32,
    pub dstRoutePrefix: u32,
    pub srcRouteLength: u8,
    pub dstRouteLength: u8,
    pub srcSecondAsn: u32,
    pub dstSecondAsn: u32,
    pub srcThirdAsn: u32,
    pub dstThirdAsn: u32,
    pub ipv6DstAddr: *const u8,
    pub ipv6SrcAddr: *const u8,
    pub srcEthMac: u64,
    pub dstEthMac: u64,
    pub ipv6SrcNextHop: *const u8,
    pub ipv6DstNextHop: *const u8,
    pub ipv6SrcRoutePrefix: *const u8,
    pub ipv6DstRoutePrefix: *const u8,
    pub isMetric: u8,

    pub customs: *const kflowCustom,
    pub numCustoms: u32,
}

#[repr(C)]
pub struct kflowByteSlice<'a> {
    pub ptr: *const u8,
    pub len: usize,
    pub ptd: PhantomData<&'a ()>,
}

#[repr(C)]
pub struct kflowDomainQuery<'a> {
    pub name: kflowByteSlice<'a>,
    pub host: kflowByteSlice<'a>,
}

#[repr(C)]
pub struct kflowDomainAnswer<'a> {
    pub ip:  kflowByteSlice<'a>,
    pub ttl: u32,
}

impl Default for kflow {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

impl From<::std::ffi::NulError> for Error {
    fn from(err: ::std::ffi::NulError) -> Error {
        Error::InvalidString(err.into_vec())
    }
}

fn pack_mac(mac: &MacAddr) -> u64 {
    let prims = mac.to_primitive_values();
    (prims.0 as u64) << 40 |
    (prims.1 as u64) << 32 |
    (prims.2 as u64) << 24 |
    (prims.3 as u64) << 16 |
    (prims.4 as u64) << 8  |
    (prims.5 as u64)
}

impl kflowCustom {
    pub fn str(id: u64, str: &CStr) -> Self {
        let str = str.as_ptr();
        Self::new(id, KFLOW_CUSTOM_STR, kflowCustomValue { str })
    }

    pub fn u8(id: u64, u8: u8) -> Self {
        Self::new(id, KFLOW_CUSTOM_U8, kflowCustomValue { u8 })
    }

    pub fn u16(id: u64, u16: u16) -> Self {
        Self::new(id, KFLOW_CUSTOM_U16, kflowCustomValue { u16 })
    }

    pub fn u32(id: u64, u32: u32) -> Self {
        Self::new(id, KFLOW_CUSTOM_U32, kflowCustomValue { u32 })
    }

    pub fn u64(id: u64, u64: u64) -> Self {
        Self::new(id, KFLOW_CUSTOM_U64, kflowCustomValue { u64 })
    }

    pub fn i8(id: u64, i8: i8) -> Self {
        Self::new(id, KFLOW_CUSTOM_I8, kflowCustomValue { i8 })
    }

    pub fn i16(id: u64, i16: i16) -> Self {
        Self::new(id, KFLOW_CUSTOM_I16, kflowCustomValue { i16 })
    }

    pub fn i32(id: u64, i32: i32) -> Self {
        Self::new(id, KFLOW_CUSTOM_I32, kflowCustomValue { i32 })
    }

    pub fn i64(id: u64, i64: i64) -> Self {
        Self::new(id, KFLOW_CUSTOM_I64, kflowCustomValue { i64 })
    }

    pub fn addr(id: u64, ip: IpAddr) -> Self {
        let mut addr = [0u8; 17];
        match ip {
            IpAddr::V4(ip) => {
                addr[0] = 4;
                addr[1..=4].copy_from_slice(&ip.octets());
            },
            IpAddr::V6(ip) => {
                addr[0] = 6;
                addr[1..17].copy_from_slice(&ip.octets());
            },
        }
        Self::new(id, KFLOW_CUSTOM_ADDR, kflowCustomValue { addr })
    }

    const fn new(id: u64, vtype: c_int, value: kflowCustomValue) -> Self {
        Self {
            name:   ptr::null(),
            id:     id,
            vtype:  vtype,
            value:  value,
        }
    }

    pub fn name(&self) -> &str {
        unsafe {
            CStr::from_ptr(self.name).to_str().unwrap_or("")
        }
    }

    pub unsafe fn get_str(&self) -> CString {
        CString::from_vec_unchecked(match self.value.str {
            ptr if ptr.is_null() => &[],
            ptr                  => CStr::from_ptr(ptr).to_bytes(),
        }.to_vec())
    }

    pub unsafe fn get_addr(&self) -> IpAddr {
        let v4 = || -> Result<[u8;  4], _> { self.value.addr[1..=4].try_into() };
        let v6 = || -> Result<[u8; 16], _> { self.value.addr[1..17].try_into() };
        match self.value.addr[0] {
            4 => IpAddr::V4(v4().unwrap().into()),
            6 => IpAddr::V6(v6().unwrap().into()),
            _ => IpAddr::V4(0.into()),
        }
    }
}

impl fmt::Debug for kflowCustom {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let name = self.name();
        let cstr: CString;
        let addr: IpAddr;

        let mut s = fmt.debug_struct("kflowCustom");
        s.field("name",  &name);
        s.field("id",    &self.id);
        s.field("vtype", &self.vtype);
        s.field("value", match self.vtype {
            KFLOW_CUSTOM_STR  => unsafe { cstr = self.get_str(); &cstr },
            KFLOW_CUSTOM_U8   => unsafe { &self.value.u8  },
            KFLOW_CUSTOM_U16  => unsafe { &self.value.u16 },
            KFLOW_CUSTOM_U64  => unsafe { &self.value.u64 },
            KFLOW_CUSTOM_U32  => unsafe { &self.value.u32 },
            KFLOW_CUSTOM_U64  => unsafe { &self.value.u64 },
            KFLOW_CUSTOM_I8   => unsafe { &self.value.i8  },
            KFLOW_CUSTOM_I16  => unsafe { &self.value.i16 },
            KFLOW_CUSTOM_I64  => unsafe { &self.value.i64 },
            KFLOW_CUSTOM_I32  => unsafe { &self.value.i32 },
            KFLOW_CUSTOM_I64  => unsafe { &self.value.i64 },
            KFLOW_CUSTOM_F32  => unsafe { &self.value.f32 },
            KFLOW_CUSTOM_F64  => unsafe { &self.value.f64 },
            KFLOW_CUSTOM_ADDR => unsafe { addr = self.get_addr(); &addr },
            _                 => panic!("kflowCustom has invalid vtype"),
        });

        s.finish()
    }
}

impl<'a> From<&'a str> for kflowByteSlice<'a> {
    fn from(str: &'a str) -> Self {
        Self {
            ptr: str.as_ptr(),
            len: str.len(),
            ptd: PhantomData,
        }
    }
}
