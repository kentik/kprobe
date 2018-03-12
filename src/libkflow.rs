#![allow(non_snake_case, unused)]

use std::default::Default;
use std::ffi::{CStr, CString};
use std::ptr;
use std::slice;
use std::net::IpAddr;
use pnet::datalink::NetworkInterface;
use pnet::util::MacAddr;
use pnet::packet::PrimitiveValues;
use time::Duration;
use libc;
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
    pub fn new(dev: &NetworkInterface, snaplen: i32, promisc: bool) -> Self {
        let program = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");

        let device  = dev.name.clone();
        let ip      = dev.ips.iter().filter(|net| net.ip().is_ipv4()).map(|net| {
            CString::new(net.ip().to_string()).unwrap()
        }).next();

        Config {
            url: CString::new("https://flow.kentik.com/chf").unwrap(),
            api: API{
                email: CString::new("test@example.com").unwrap(),
                token: CString::new("token").unwrap(),
                url:   CString::new("https://api.kentik.com/api/internal").unwrap(),
            },
            capture: Capture{
                device:  CString::new(device).unwrap(),
                snaplen: snaplen,
                promisc: promisc,
                ip:      ip,
            },
            metrics: Metrics{
                interval: Duration::minutes(1),
                url:      CString::new("https://flow.kentik.com/tsdb").unwrap(),
            },
            proxy:   None,
            status:  Status{
                host: CString::new("127.0.0.1").unwrap(),
                port: 0,
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
    fn opt(cstr: &Option<CString>) -> *const libc::c_char {
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
            promisc: cfg.capture.promisc as libc::c_int,
            ip:      opt(&cfg.capture.ip),
        },
        metrics: kflowConfigMetrics {
            interval: cfg.metrics.interval.num_minutes() as libc::c_int,
            URL:      cfg.metrics.url.as_ptr(),
        },
        proxy: kflowConfigProxy {
            URL: opt(&cfg.proxy),
        },
        status: kflowConfigStatus {
            host: cfg.status.host.as_ptr(),
            port: cfg.status.port as libc::c_int,
        },
        device_id:   cfg.device_id as libc::c_int,
        device_if:   opt(&cfg.device_if),
        device_ip:   opt(&cfg.device_ip),
        device_name: cfg.device_name.as_ptr(),
        device_plan: cfg.device_plan.unwrap_or(0) as libc::c_int,
        device_site: cfg.device_site.unwrap_or(0) as libc::c_int,
        sample:      cfg.sample as libc::c_int,
        timeout:     cfg.timeout.num_milliseconds() as libc::c_int,
        verbose:     cfg.verbose as libc::c_int,
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
        match kflowStop(timeout.num_milliseconds() as libc::c_int) {
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

        let ptr = bytes.as_mut_ptr() as *mut libc::c_char;
        let len = bytes.len();
        libc::gethostname(ptr, len);

        CStr::from_ptr(ptr).to_owned()
    }
}

#[link(name = "kflow")]
extern {
    fn kflowInit(cfg: *const kflowConfig, dev: *mut kflowDevice) -> libc::c_int;
    fn kflowSend(flow: *const kflow) -> libc::c_int;
    fn kflowStop(timeout: libc::c_int) -> libc::c_int;
    fn kflowError() -> *const libc::c_char;
    fn kflowVersion() -> *const libc::c_char;
}

pub const KFLOW_CUSTOM_STR: libc::c_int = 1;
pub const KFLOW_CUSTOM_U32: libc::c_int = 2;
pub const KFLOW_CUSTOM_F32: libc::c_int = 3;

#[repr(C)]
struct kflowConfig {
    URL:         *const libc::c_char,
    API:         kflowConfigAPI,
    capture:     kflowConfigCapture,
    metrics:     kflowConfigMetrics,
    proxy:       kflowConfigProxy,
    status:      kflowConfigStatus,
    device_id:   libc::c_int,
    device_if:   *const libc::c_char,
    device_ip:   *const libc::c_char,
    device_name: *const libc::c_char,
    device_plan: libc::c_int,
    device_site: libc::c_int,
    sample:      libc::c_int,
    timeout:     libc::c_int,
    verbose:     libc::c_int,
    program:     *const libc::c_char,
    version:     *const libc::c_char,
}

#[repr(C)]
struct kflowConfigAPI {
    email: *const libc::c_char,
    token: *const libc::c_char,
    URL:   *const libc::c_char,
}

#[repr(C)]
struct kflowConfigCapture {
    device:  *const libc::c_char,
    snaplen: libc::c_int,
    promisc: libc::c_int,
    ip:      *const libc::c_char,
}

#[repr(C)]
struct kflowConfigMetrics {
    interval: libc::c_int,
    URL:      *const libc::c_char,
}

#[repr(C)]
struct kflowConfigProxy {
    URL: *const libc::c_char,
}

#[repr(C)]
struct kflowConfigStatus {
    host: *const libc::c_char,
    port: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct kflowCustom {
    pub name:  *const libc::c_char,
    pub id:    u64,
    pub vtype: libc::c_int,
    pub value: kflowCustomValue,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union kflowCustomValue {
    pub str: *const libc::c_char,
    pub u32: u32,
    pub f32: f32,
}

#[repr(C)]
pub struct kflowDevice {
    pub id:          u64,
    pub name:        *const libc::c_char,
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

    pub customs: *const kflowCustom,
    pub numCustoms: u32,
}

impl kflowCustom {
    pub fn name(&self) -> &str {
        unsafe {
            CStr::from_ptr(self.name).to_str().unwrap_or("")
        }
    }
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
    pub fn set_str(&mut self, str: &CStr) {
        self.vtype = KFLOW_CUSTOM_STR;
        unsafe { self.value.str = str.as_ptr(); }
    }

    pub fn set_u32(&mut self, u32: u32) {
        self.vtype = KFLOW_CUSTOM_U32;
        unsafe { self.value.u32 = u32; }
    }
}

impl ::std::fmt::Debug for kflowCustom {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        let name = unsafe { CStr::from_ptr(self.name).to_str().unwrap_or("") };
        let cstr: &CStr;

        let mut s = fmt.debug_struct("kflowCustom");
        s.field("name",  &name);
        s.field("id",    &self.id);
        s.field("vtype", &self.vtype);
        s.field("value", match self.vtype {
            KFLOW_CUSTOM_STR => unsafe { cstr = CStr::from_ptr(self.value.str); &cstr },
            KFLOW_CUSTOM_U32 => unsafe { &self.value.u32 },
            KFLOW_CUSTOM_F32 => unsafe { &self.value.f32 },
            _                => panic!("kflowCustom has invalid vtype"),
        });

        s.finish()
    }
}
