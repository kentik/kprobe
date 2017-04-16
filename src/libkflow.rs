#![allow(non_snake_case, unused)]

use std::borrow::Cow;
use std::default::Default;
use std::ffi::{CStr, CString};
use std::ptr;
use std::net::IpAddr;
use pnet::util::MacAddr;
use pnet::packet::PrimitiveValues;
use chrono::Duration;
use libc;
use super::flow::Protocol;
use super::queue::{Key, Counter, Direction};

pub struct Config<'a> {
    pub url:       Cow<'a, str>,
    pub api:       API<'a>,
    pub metrics:   Metrics<'a>,
    pub proxy:     Option<Cow<'a, str>>,
    pub device_id: u32,
    pub timeout:   Duration,
    pub verbose:   u32,
}

pub struct API<'a> {
    pub email: Cow<'a, str>,
    pub token: Cow<'a, str>,
    pub url:   Cow<'a, str>,
}

pub struct Metrics<'a> {
    pub interval: Duration,
    pub url:      Cow<'a, str>,
}

#[derive(Debug)]
pub enum Error {
    InvalidString(Vec<u8>),
    InvalidConfig,
    Timeout,
    Failed(u32),
}

impl<'a> Config<'a> {
    pub fn new() -> Self {
        Config {
            url: Cow::from("https://flow.kentik.com/chf"),
            api: API {
                email: Cow::from("test@example.com"),
                token: Cow::from("token"),
                url:   Cow::from("https://api.kentik.com/api/v5"),
            },
            metrics: Metrics {
                interval: Duration::seconds(1),
                url:      Cow::from("https://flow.kentik.com/tsdb"),
            },
            proxy:     None,
            device_id: 1,
            timeout:   Duration::seconds(0),
            verbose:   0,
        }
    }
}

pub fn configure(cfg: &Config) -> Result<(), Error> {
    let flow_url    = CString::new(cfg.url.as_bytes())?;
    let api_url     = CString::new(cfg.api.url.as_bytes())?;
    let email       = CString::new(cfg.api.email.as_bytes())?;
    let token       = CString::new(cfg.api.token.as_bytes())?;
    let metrics_url = CString::new(cfg.metrics.url.as_bytes())?;
    let proxy_url   = if let Some(ref url) = cfg.proxy {
        Some(CString::new(url.as_bytes())?)
    } else {
        None
    };

    let c_cfg = kflowConfig {
        URL: flow_url.as_ptr(),
        API: kflowConfigAPI {
            email: email.as_ptr(),
            token: token.as_ptr(),
            URL:   api_url.as_ptr(),

        },
        metrics: kflowConfigMetrics {
            interval: cfg.metrics.interval.num_seconds() as libc::c_int,
            URL:      metrics_url.as_ptr(),
        },
        proxy: kflowConfigProxy {
            URL: proxy_url.map(|p| p.as_ptr()).unwrap_or(ptr::null()),
        },
        device_id: cfg.device_id as libc::c_int,
        device_if: ptr::null(),
        device_ip: ptr::null(),
        timeout:   cfg.timeout.num_milliseconds() as libc::c_int,
        verbose:   cfg.verbose as libc::c_int,
    };

    unsafe {
        match kflowInit(&c_cfg, ptr::null_mut(), ptr::null_mut()) {
            0 => Ok(()),
            1 => Err(Error::InvalidConfig),
            n => Err(Error::Failed(n as u32))
        }
    }
}

pub fn send(key: &Key, ctr: &Counter) -> Result<(), Error> {
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

    kflow.srcEthMac = pack_mac(&ctr.ethernet.src);
    kflow.dstEthMac = pack_mac(&ctr.ethernet.dst);
    kflow.tos       = ctr.tos as u32;
    kflow.l4SrcPort = key.1.port as u32;
    kflow.l4DstPort = key.2.port as u32;
    kflow.tcpFlags  = ctr.tcp_flags as u32;
    kflow.sampleRate = 1;

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

#[link(name = "kflow")]
extern {
    fn kflowInit(cfg: *const kflowConfig, customs: *mut *mut kflowCustom, numCustoms: *mut u32) -> libc::c_int;
    fn kflowSend(flow: *const kflow) -> libc::c_int;
    fn kflowStop(timeout: libc::c_int) -> libc::c_int;
    fn kflowError() -> *const libc::c_char;
    fn kflowVersion() -> *const libc::c_char;
}

#[repr(C)]
struct kflowConfig {
    URL:       *const libc::c_char,
    API:       kflowConfigAPI,
    metrics:   kflowConfigMetrics,
    proxy:     kflowConfigProxy,
    device_id: libc::c_int,
    device_if: *const libc::c_char,
    device_ip: *const libc::c_char,
    timeout:   libc::c_int,
    verbose:   libc::c_int,
}

#[repr(C)]
struct kflowConfigAPI {
    email: *const libc::c_char,
    token: *const libc::c_char,
    URL:   *const libc::c_char,
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
pub struct kflowCustom {
    pub name:  *const libc::c_char,
    pub id:    u64,
    pub vtype: libc::c_int,
    pub value: kflowCustomValue,
}

#[repr(C)]
pub union kflowCustomValue {
    pub str: *const libc::c_char,
    pub u32: u32,
    pub f32: f32,
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
    pub customs: *const kflowCustom,
    pub numCustoms: u32,
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
