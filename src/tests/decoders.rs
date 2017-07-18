use std::borrow::Cow;
use std::ffi::CStr;
use libc::c_char;
use libkflow::*;
use custom::Customs;
use protocol::Decoders;
use super::iter;

#[test]
fn decode_http() {
    let mut decoders = Decoders::new(CUSTOMS);
    let mut customs  = Customs::new(CUSTOMS);

    let mut req_url:    Option<Value> = None;
    let mut req_host:   Option<Value> = None;
    let mut req_ua:     Option<Value> = None;
    let mut res_status: Option<Value> = None;
    let mut latency:    Option<Value> = None;

    for flow in iter::flows("pcaps/http/google.com.pcap") {
        let d = decoders.classify(&flow);
        decoders.decode(d, &flow, &mut customs);

        req_url    = value("KFLOW_HTTP_URL", &customs).or_else(|| req_url);
        req_host   = value("KFLOW_HTTP_HOST", &customs).or_else(|| req_host);
        req_ua     = value("KFLOW_HTTP_UA", &customs).or_else(|| req_ua);
        res_status = value("KFLOW_HTTP_STATUS", &customs).or_else(|| res_status);
        latency    = value("APPL_LATENCY_MS", &customs).or_else(|| latency);

        customs.clear();
    }

    assert_eq!(Some(Value::from("/")), req_url);
    assert_eq!(Some(Value::from("google.com")), req_host);
    assert_eq!(Some(Value::from("curl/7.38.0")), req_ua);
    assert_eq!(Some(Value::from(302)), res_status);
    assert_eq!(Some(Value::from(7)),latency);
}

#[test]
fn decode_dns() {
    let mut decoders = Decoders::new(CUSTOMS);
    let mut customs  = Customs::new(CUSTOMS);

    let mut query_name: Option<Value> = None;
    let mut query_type: Option<Value> = None;
    let mut reply_code: Option<Value> = None;
    let mut reply_data: Option<Value> = None;
    let mut latency:    Option<Value> = None;

    for flow in iter::flows("pcaps/dns/google.com-any.pcap").take(2) {
        let d = decoders.classify(&flow);
        decoders.decode(d, &flow, &mut customs);


        query_name = value("KFLOW_DNS_QUERY", &customs).or_else(|| query_name);
        query_type = value("KFLOW_DNS_QUERY_TYPE", &customs).or_else(|| query_type);
        reply_code = value("KFLOW_DNS_RET_CODE", &customs).or_else(|| reply_code);
        reply_data = value("KFLOW_DNS_RESPONSE", &customs).or_else(|| reply_data);
        latency    = value("APPL_LATENCY_MS", &customs).or_else(|| latency);

        customs.clear();
    }

    let reply = "172.217.26.14/A;2404:6800:4004:809::200e/AAAA;alt2.aspmx.l.google.com/MX;ns2.google.com/NS;;alt4.aspmx.l.google.com/MX;aspmx.l.google.com/MX;ns4.google.com/NS;alt3.aspmx.l.google.com/MX;alt1.aspmx.l.google.com/MX;v=spf1 include:_spf.google.com ~all/TXT;;ns1.google.com/NS;;ns3.google.com/NS";

    assert_eq!(Some(Value::from("google.com")), query_name);
    assert_eq!(Some(Value::from(255)), query_type);
    assert_eq!(Some(Value::from(0)), reply_code);
    assert_eq!(Some(Value::from(reply)), reply_data);
    assert_eq!(Some(Value::from(44)), latency);
}

#[test]
fn decode_tls_handshake() {
    let mut decoders = Decoders::new(CUSTOMS);
    let mut customs  = Customs::new(CUSTOMS);

    let mut server_name: Option<Value> = None;

    for flow in iter::flows("pcaps/tls/google.com-tls-1.2.pcap") {
        let key = flow.key();

        let d = decoders.classify(&flow);
        decoders.decode(d, &flow, &mut customs);
        decoders.append(d, &key,  &mut customs);

        server_name = value("KFLOW_HTTP_HOST", &customs).or_else(|| server_name);

        customs.clear();
    }

    assert_eq!(Some(Value::from("google.com")), server_name);
}

#[test]
fn decode_tls_ignore_established() {
    let mut decoders = Decoders::new(CUSTOMS);
    let mut customs  = Customs::new(CUSTOMS);

    for flow in iter::flows("pcaps/tls/google.com-tls-1.2.pcap").skip(2) {
        let key = flow.key();

        let d = decoders.classify(&flow);
        decoders.decode(d, &flow, &mut customs);
        decoders.append(d, &key,  &mut customs);
    }

    assert_eq!(0, customs.len());
}

const CUSTOMS: &[kflowCustom] = &[
    custom(b"APPL_LATENCY_MS\0",      01, KFLOW_CUSTOM_U32),
    custom(b"KFLOW_DNS_QUERY\0",      02, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_DNS_QUERY_TYPE\0", 03, KFLOW_CUSTOM_U32),
    custom(b"KFLOW_DNS_RET_CODE\0",   04, KFLOW_CUSTOM_U32),
    custom(b"KFLOW_DNS_RESPONSE\0",   05, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_URL\0",       06, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_HOST\0",      07, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_REFERER\0",   08, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_UA\0",        09, KFLOW_CUSTOM_STR),
    custom(b"KFLOW_HTTP_STATUS\0",    10, KFLOW_CUSTOM_U32),
];

const fn custom(name: &[u8], id: u64, vtype: ::libc::c_int) -> kflowCustom {
    kflowCustom{
        name:  name as *const [u8] as *const u8 as *const i8,
        id:    id,
        vtype: vtype,
        value: kflowCustomValue{u32: 0},
    }
}

#[derive(Debug, PartialEq)]
enum Value {
    Str(String),
    U32(u32),
    F32(f32),
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

impl<'a> From<&'a kflowCustom> for Value {
    fn from(c: &'a kflowCustom) -> Value {
        match c.vtype {
            KFLOW_CUSTOM_STR => unsafe { c.value.str.into()      },
            KFLOW_CUSTOM_U32 => unsafe { Value::U32(c.value.u32) },
            KFLOW_CUSTOM_F32 => unsafe { Value::F32(c.value.f32) },
            _                => panic!("kflowCustom has invalid vtype"),
        }
    }
}

fn value(name: &str, cs: &[kflowCustom]) -> Option<Value> {
    CUSTOMS.iter().find(|c| c.name() == name).and_then(|custom| {
        cs.iter().find(|c| c.id == custom.id).map(Value::from)
    })
}

// fn dump(cs: &[kflowCustom]) {
//     for c in cs {
//         if let Some(def) = CUSTOMS.iter().find(|def| def.id == c.id) {
//             let name  = def.name();
//             let value = Value::from(c);
//             println!("{} => {:?}", name, value);
//         } else {
//             println!("unknown custom column ID: {}", c.id);
//         }
//     }
// }
