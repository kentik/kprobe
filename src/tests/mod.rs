mod config;
mod iter;
mod decoders;
mod sampling;
mod export;
mod modes;

use std::borrow::Cow;
use std::ffi::CStr;
use std::mem::swap;
use std::net::IpAddr;
use std::time::{UNIX_EPOCH, SystemTime};
use libc::{c_char, c_int};
use pcap::Capture;
use pnet::packet::{Packet as PacketExt, PacketSize};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use time::Duration;
use crate::libkflow::*;
use crate::flow::*;
use crate::packet;
use crate::custom::*;
use crate::protocol::{Classify, Decoder};
use crate::reasm::Reassembler;
use crate::time::Timestamp;
use crate::timer::{Timer, Timeout};
use crate::track::Tracker;
use crate::track::id::Generator;

#[test]
fn timer_ready() {
    let mut timer = Timer::new(Duration::seconds(2));
    let ts = Timestamp::zero();

    assert_eq!(true,  timer.ready(ts)); // timer starts ready
    assert_eq!(false, timer.ready(ts + Duration::seconds(1)));
    assert_eq!(true,  timer.ready(ts + Duration::seconds(2)));
    assert_eq!(false, timer.ready(ts + Duration::seconds(3)));
    assert_eq!(true,  timer.ready(ts + Duration::seconds(4)));
}

#[test]
fn timeout_range() {
    let max = Duration::seconds(2);
    let mut timeout = Timeout::new(max);
    let zero = Timestamp::zero();

    for i in 0..10 {
        let start = zero + Duration::seconds(i);
        let first = timeout.first(start);
        assert!(first >= start && first <= start + max);
    }
}

#[test]
fn time_sanity_checks() {
    let system    = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let timestamp = Timestamp::now().sec;
    assert!(timestamp >= system);
    assert!(timestamp - system < 2);

    let timestamp = Timestamp::zero() + Duration::seconds(2);
    assert_eq!(2, timestamp.sec);

    let timestamp0 = Timestamp::zero() + Duration::seconds(2);
    let timestamp1 = Timestamp::zero() + Duration::seconds(4);
    assert_eq!(Duration::seconds(2), timestamp1 - timestamp0);
}

#[test]
fn test_decode_wrong_ipv4_length() {
    let mut cap = Capture::from_file("pcaps/dns/sns-pb.isc.org.pcap").unwrap();
    let pkt = cap.next_packet().unwrap();
    let eth = EthernetPacket::new(&pkt.data).unwrap();

    let udp_payload_len = |add: i16| -> usize {
        let mut pkt = MutableIpv4Packet::owned(eth.payload().to_vec()).unwrap();
        let len = pkt.get_total_length() as i16 + add;
        pkt.set_total_length(len as u16);

        let pkt = packet::Packet::IPv4(pkt.to_immutable());

        match pkt.transport(pkt.payload()) {
            Some(packet::Transport::UDP(udp)) => udp.payload().len(),
            _                                 => unreachable!(),
        }
    };

    assert_eq!(32, udp_payload_len(  0));
    assert_eq!(32, udp_payload_len( 20));
    assert_eq!(12, udp_payload_len(-20));
}

#[test]
fn test_reassemble_single() {
    let mut cap = Capture::from_file("pcaps/dns/sns-pb.isc.org.pcap").unwrap();
    let mut asm = Reassembler::new();

    while let Ok(pkt) = cap.next_packet() {
        let ts  = Timestamp::from(pkt.header.ts);
        let eth = EthernetPacket::new(pkt.data).unwrap();
        let len = pkt.header.len as usize - eth.packet_size();

        let pkt = packet::decode(&eth).1.unwrap();
        let out = asm.reassemble(ts, &pkt).unwrap();

        assert_eq!(out.packets, 1);
        assert_eq!(out.frags,   0);
        assert_eq!(out.bytes,   len);
    }
}

#[test]
fn test_reassemble_fragmented() {
    let mut cap = Capture::from_file("pcaps/dns/sns-pb.isc.org-dnssec.pcap").unwrap();
    let mut asm = Reassembler::new();

    cap.next_packet().unwrap();

    let mut packets = 0;
    let mut frags   = 0;
    let mut bytes   = 0;
    let mut done    = false;

    while let Ok(pkt) = cap.next_packet() {
        let ts  = Timestamp::from(pkt.header.ts);
        let eth = EthernetPacket::new(pkt.data).unwrap();
        let len = pkt.header.len as usize - eth.packet_size();

        packets += 1;
        frags   += 1;
        bytes   += len;

        let pkt = packet::decode(&eth).1.unwrap();

        if let Some(out) = asm.reassemble(ts, &pkt) {
            assert_eq!(out.packets, packets);
            assert_eq!(out.frags,   frags);
            assert_eq!(out.bytes,   bytes);
            done = true;
        }
    }

    assert!(done);
}

#[test]
fn test_udp_first_exchange_latency() {
    let mut trk = Tracker::new(&Customs::new(&CUSTOMS));

    for flow in iter::flows("pcaps/dns/google.com-any.pcap") {
        trk.add(&flow);
    }

    let src = Addr{addr: "10.0.0.52".parse().unwrap(), port: 52407};
    let dst = Addr{addr: "8.8.4.4".parse().unwrap(),   port: 53   };
    let key = Key(Protocol::UDP, dst, src);

    assert_eq!(Some(44), trk.latency(&key).map(|d| d.whole_milliseconds()));

    let mut customs = Customs::new(&CUSTOMS);
    trk.append(&key, &mut customs);

    assert_eq!(Some(Value::from(44)), value(FPX_LATENCY, &customs));
}

#[test]
fn test_tcp_first_exchange_latency() {
    let mut trk = Tracker::new(&Customs::new(&CUSTOMS));

    for flow in iter::flows("pcaps/http/google.com.pcap") {
        if flow.tcp_flags() & FIN == FIN {
            break;
        }
        trk.add(&flow);
    }

    let src = Addr{addr: "10.211.55.16".parse().unwrap(),   port: 42370};
    let dst = Addr{addr: "172.217.25.110".parse().unwrap(), port: 80   };
    let key = Key(Protocol::TCP, dst, src);

    assert_eq!(Some(7), trk.latency(&key).map(|d| d.whole_milliseconds()));

    let mut customs = Customs::new(&CUSTOMS);
    trk.append(&key, &mut customs);

    assert_eq!(Some(Value::from(7)), value(FPX_LATENCY, &customs));
}

#[test]
fn test_tcp_retransmits() {
    let mut trk = Tracker::new(&Customs::new(&CUSTOMS));

    for flow in iter::flows("pcaps/tcp/retransmits.pcap") {
        trk.add(&flow);
    }

    let src  = "10.211.55.2".parse().unwrap();
    let dst  = Addr{addr: "10.211.55.16".parse().unwrap(), port: 2222};
    let key0 = Key(Protocol::TCP, Addr{addr: src, port: 52952}, dst);
    let key1 = Key(Protocol::TCP, Addr{addr: src, port: 52953}, dst);

    assert_eq!(Some((8, 1)), trk.retransmits(&key0));
    assert_eq!(Some((6, 1)), trk.retransmits(&key1));

    let mut customs = Customs::new(&CUSTOMS);
    trk.append(&key0, &mut customs);

    assert_eq!(Some(Value::from(8)), value(RETRANSMITTED_OUT, &customs));
    assert_eq!(Some(Value::from(1)), value(REPEATED_RETRANSMITS, &customs));

    customs.clear();
    trk.append(&key1, &mut customs);

    assert_eq!(Some(Value::from(6)), value(RETRANSMITTED_OUT, &customs));
    assert_eq!(Some(Value::from(1)), value(REPEATED_RETRANSMITS, &customs));
}

#[test]
fn test_tcp_receive_window() {
    let mut trk = Tracker::new(&Customs::new(&CUSTOMS));
    let windows = [65535, 1024, 131744, 131744, 0, 1024];

    for (flow, window) in iter::flows("pcaps/tcp/zero_windows.pcap").zip(windows.iter()) {
        let mut customs = Customs::new(&CUSTOMS);
        let window = Value::from(*window);

        trk.add(&flow);
        trk.append(&flow.key(), &mut customs);

        assert_eq!(Some(window), value(RECEIVE_WINDOW, &customs));
    }

    let mut trk = Tracker::new(&Customs::new(&CUSTOMS));

    for flow in iter::flows("pcaps/tcp/zero_windows.pcap").skip(2) {
        let mut customs = Customs::new(&CUSTOMS);

        trk.add(&flow);
        trk.append(&flow.key(), &mut customs);

        assert_eq!(None, value(RECEIVE_WINDOW, &customs));
    }
}

#[test]
fn test_tcp_zero_windows() {
    let mut trk = Tracker::new(&Customs::new(&CUSTOMS));

    for flow in iter::flows("pcaps/tcp/zero_windows.pcap") {
        trk.add(&flow);
    }

    let src = Addr{addr: "10.211.55.16".parse().unwrap(), port: 2222};
    let dst = Addr{addr: "10.211.55.2".parse().unwrap(),  port: 58377};
    let key = Key(Protocol::TCP, src, dst);

    assert_eq!(Some(10), trk.zwindows(&key));

    let mut customs = Customs::new(&CUSTOMS);
    trk.append(&key, &mut customs);

    assert_eq!(Some(Value::from(10)), value(ZERO_WINDOWS, &customs));
}

#[test]
fn test_id_generator() {
    let g = Generator::new();
    let mut a = flow(23, 31, false);
    let mut b = flow(31, 23, false);

    a.ethernet.vlan = Some(41);
    b.ethernet.vlan = Some(41);
    swap(&mut b.ethernet.src, &mut b.ethernet.dst);
    a.direction = Direction::Out;
    b.direction = Direction::In;

    let a = g.id(&a);
    let b = g.id(&b);
    assert_eq!(a, b);
}

#[test]
fn test_connection_id() {
    let mut trk = Tracker::new(&Customs::new(&CUSTOMS));

    let mut a = flow(23, 31, false);
    let mut b = flow(31, 23, false);

    swap(&mut b.ethernet.src, &mut b.ethernet.dst);
    a.direction = Direction::Out;
    b.direction = Direction::In;

    trk.add(&a);
    trk.add(&b);

    let mut customs = Customs::new(&CUSTOMS);

    trk.append(&a.key(), &mut customs);
    let ida = value(CONNECTION_ID, &customs);
    assert!(ida.is_some());

    customs.clear();

    trk.append(&b.key(), &mut customs);
    let idb = value(CONNECTION_ID, &customs);
    assert!(idb.is_some());

    assert_eq!(ida, idb);
}

#[test]
fn test_ignore_ipv4_ethernet_padding() {
    let mut cap = Capture::from_file("pcaps/ip/ipv4_eth_padding.pcap").unwrap();

    while let Ok(pkt) = cap.next_packet() {
        let eth = EthernetPacket::new(pkt.data).unwrap();
        let ip  = Ipv4Packet::new(eth.payload()).unwrap();
        let pkt = packet::decode(&eth).1.unwrap();

        let tcp = match pkt.transport(ip.payload()) {
            Some(packet::Transport::TCP(tcp)) => tcp,
            _                                 => unreachable!(),
        };

        assert_eq!(0, tcp.payload().len());
    }
}

#[test]
fn test_min_max_latency() {
    let mut customs = Customs::new(&CUSTOMS);

    customs.add_latency(0, Duration::seconds(1));
    customs.add_latency(0, Duration::seconds(60));
    customs.add_latency(0, Duration::seconds(0));

    assert_eq!(unsafe { customs[0].value.u32 }, 1000);
    assert_eq!(unsafe { customs[1].value.u32 }, 20000);
    assert_eq!(unsafe { customs[2].value.u32 }, 1);
}

pub const CUSTOMS: &[kflowCustom] = &[
    custom(b"FRAGMENTS\0",              01, KFLOW_CUSTOM_U32),
    custom(b"APPL_LATENCY_MS\0",        02, KFLOW_CUSTOM_U32),
    custom(b"FPEX_LATENCY_MS\0",        03, KFLOW_CUSTOM_U32),
    custom(b"CLIENT_NW_LATENCY_MS\0",   04, KFLOW_CUSTOM_U32),
    custom(b"SERVER_NW_LATENCY_MS\0",   05, KFLOW_CUSTOM_U32),
    custom(b"RETRANSMITTED_OUT_PKTS\0", 06, KFLOW_CUSTOM_U32),
    custom(b"REPEATED_RETRANSMITS\0",   07, KFLOW_CUSTOM_U32),
    custom(b"OOORDER_IN_PKTS\0",        08, KFLOW_CUSTOM_U32),
    custom(b"RECEIVE_WINDOW\0",         09, KFLOW_CUSTOM_U32),
    custom(b"ZERO_WINDOWS\0",           10, KFLOW_CUSTOM_U32),
    custom(b"CONNECTION_ID\0",          11, KFLOW_CUSTOM_U32),
    custom(b"APP_PROTOCOL\0",           12, KFLOW_CUSTOM_U32),
    custom(b"INT00\0",                  13, KFLOW_CUSTOM_U32),
    custom(b"INT01\0",                  14, KFLOW_CUSTOM_U32),
    custom(b"INT02\0",                  15, KFLOW_CUSTOM_U32),
    custom(b"INT03\0",                  16, KFLOW_CUSTOM_U32),
    custom(b"INT04\0",                  17, KFLOW_CUSTOM_U32),
    custom(b"INT05\0",                  18, KFLOW_CUSTOM_U32),
    custom(b"STR00\0",                  19, KFLOW_CUSTOM_STR),
    custom(b"STR01\0",                  20, KFLOW_CUSTOM_STR),
    custom(b"STR02\0",                  21, KFLOW_CUSTOM_STR),
    custom(b"STR03\0",                  22, KFLOW_CUSTOM_STR),
    custom(b"INET_00\0",                23, KFLOW_CUSTOM_ADDR),
    custom(b"INET_01\0",                24, KFLOW_CUSTOM_ADDR),
    custom(b"INET_02\0",                25, KFLOW_CUSTOM_ADDR),
];

pub const _CUSTOMS: &[kflowCustom] = &[
    custom(b"FRAGMENTS\0",              01, KFLOW_CUSTOM_U32),
    custom(b"APPL_LATENCY_MS\0",        02, KFLOW_CUSTOM_U32),
    custom(b"FPEX_LATENCY_MS\0",        03, KFLOW_CUSTOM_U32),
    custom(b"KFLOW_DNS_QUERY\0",        04, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_DNS_QUERY_TYPE\0",   05, KFLOW_CUSTOM_U32),
    custom(b"KFLOW_DNS_RET_CODE\0",     06, KFLOW_CUSTOM_U32),
    custom(b"KFLOW_DNS_RESPONSE\0",     07, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_URL\0",         08, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_HOST\0",        09, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_REFERER\0",     10, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_UA\0",          11, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_STATUS\0",      12, KFLOW_CUSTOM_U32),
    custom(b"CLIENT_NW_LATENCY_MS\0",   13, KFLOW_CUSTOM_U32),
    custom(b"SERVER_NW_LATENCY_MS\0",   14, KFLOW_CUSTOM_U32),
    custom(b"RETRANSMITTED_IN_PKTS\0",  15, KFLOW_CUSTOM_U32),
    custom(b"RETRANSMITTED_OUT_PKTS\0", 16, KFLOW_CUSTOM_U32),
    custom(b"REPEATED_RETRANSMITS\0",   17, KFLOW_CUSTOM_U32),
    custom(b"OOORDER_IN_PKTS\0",        18, KFLOW_CUSTOM_U32),
    custom(b"OOORDER_OUT_PKTS\0",       19, KFLOW_CUSTOM_U32),
    custom(b"RECEIVE_WINDOW\0",         20, KFLOW_CUSTOM_U32),
    custom(b"ZERO_WINDOWS\0",           21, KFLOW_CUSTOM_U32),
    custom(b"CONNECTION_ID\0",          22, KFLOW_CUSTOM_U32),
];

const fn custom(name: &'static [u8], id: u64, vtype: c_int) -> kflowCustom {
    kflowCustom{
        name:  name.as_ptr() as *const c_char,
        id:    id,
        vtype: vtype,
        value: kflowCustomValue{u32: 0},
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Str(String),
    U8 (u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8 (i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Addr(IpAddr),
}

impl<'a> From<&'a str> for Value {
    fn from(s: &'a str) -> Self {
        Value::Str(s.to_owned())
    }
}

impl From<*const c_char> for Value {
    fn from(p: *const c_char) -> Self {
        Value::Str(match p.is_null() {
            true  => Cow::from("NULL"),
            false => unsafe { CStr::from_ptr(p).to_string_lossy() },
        }.into_owned())
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::U32(n)
    }
}

impl From<IpAddr> for Value {
    fn from(ip: IpAddr) -> Self {
        Value::Addr(ip)
    }
}

impl<'a> From<&'a kflowCustom> for Value {
    fn from(c: &'a kflowCustom) -> Value {
        match c.vtype {
            KFLOW_CUSTOM_STR  => unsafe { c.value.str.into()        },
            KFLOW_CUSTOM_U8   => unsafe { Value::U8 (c.value.u8)    },
            KFLOW_CUSTOM_U16  => unsafe { Value::U16(c.value.u16)   },
            KFLOW_CUSTOM_U32  => unsafe { Value::U32(c.value.u32)   },
            KFLOW_CUSTOM_U64  => unsafe { Value::U64(c.value.u64)   },
            KFLOW_CUSTOM_I8   => unsafe { Value::I8 (c.value.i8)    },
            KFLOW_CUSTOM_I16  => unsafe { Value::I16(c.value.i16)   },
            KFLOW_CUSTOM_I32  => unsafe { Value::I32(c.value.i32)   },
            KFLOW_CUSTOM_I64  => unsafe { Value::I64(c.value.i64)   },
            KFLOW_CUSTOM_F32  => unsafe { Value::F32(c.value.f32)   },
            KFLOW_CUSTOM_F64  => unsafe { Value::F64(c.value.f64)   },
            KFLOW_CUSTOM_ADDR => unsafe { Value::Addr(c.get_addr()) },
            _                => panic!("kflowCustom has invalid vtype"),
        }
    }
}

pub fn value(name: &str, cs: &Customs) -> Option<Value> {
    cs.get(name).ok().and_then(|id| cs.iter().find(|c| c.id == id).map(Value::from))
}

pub fn classifier() -> Classify {
    let mut classify = Classify::new();
    classify.add(Protocol::TCP, 22,   Decoder::TLS);
    classify.add(Protocol::TCP, 80,   Decoder::HTTP);
    classify.add(Protocol::UDP, 53,   Decoder::DNS);
    classify.add(Protocol::UDP, 1812, Decoder::Radius);
    classify.add(Protocol::UDP, 1813, Decoder::Radius);
    classify
}

fn flow<'a>(src: u32, dst: u32, export: bool) -> Flow<'a> {
    Flow{
        timestamp: Timestamp::zero(),
        ethernet:  Ethernet{
            src:  "00:01:02:03:04:05".parse().unwrap(),
            dst:  "00:0a:0b:0c:0d:0e".parse().unwrap(),
            vlan:  None,
        },
        protocol:  Protocol::TCP,
        src:       Addr{addr: IpAddr::V4(src.into()), port: src as u16},
        dst:       Addr{addr: IpAddr::V4(dst.into()), port: dst as u16},
        tos:       7,
        transport: Transport::TCP{seq: 11, flags: SYN, window: Default::default()},
        packets:   13,
        fragments: 17,
        bytes:     19,
        direction: Direction::Out,
        export:    export,
        ..Default::default()
    }
}
