use time::Duration;
use crate::custom::Customs;
use crate::protocol::{Classify, Decoder, Decoders};
use crate::queue::Counter;
use super::*;

#[test]
fn decode_dhcp() {
    let mut customs  = Customs::new(&CUSTOMS);
    let mut classify = Classify::new();
    let mut decoders = Decoders::new(&customs, &mut classify, true);

    let mut flows = iter::flows("pcaps/dhcp/dhcpv4.pcap");

    let mac     = Value::from("00:1c:42:60:bb:37");
    let host    = Value::from("chdev");
    let noaddr  = Value::from("0.0.0.0".parse::<IpAddr>().unwrap());
    let domain  = Value::from("localdomain");
    let yiaddr  = Value::from("10.211.55.16".parse::<IpAddr>().unwrap());
    let siaddr  = Value::from("10.211.55.1".parse::<IpAddr>().unwrap());
    let lease   = Value::from(1800);

    // Request
    let flow = flows.next().unwrap();
    decoders.decode(classify.find(&flow), &flow, &mut customs);

    assert_eq!(Some(Value::from(1)), value(DHCP_OP, &customs));
    assert_eq!(Some(Value::from(3)), value(DHCP_MSG_TYPE, &customs));
    assert_eq!(Some(noaddr.clone()), value(DHCP_CI_ADDR, &customs));
    assert_eq!(Some(noaddr.clone()), value(DHCP_YI_ADDR, &customs));
    assert_eq!(Some(noaddr.clone()), value(DHCP_SI_ADDR, &customs));
    assert_eq!(Some(mac.clone()),    value(DHCP_CH_ADDR, &customs));
    assert_eq!(Some(host.clone()),   value(DHCP_HOSTNAME, &customs));
    assert_eq!(None,                 value(DHCP_DOMAIN, &customs));
    assert_eq!(None,                 value(DHCP_LEASE, &customs));
    assert_eq!(None,                 value(APP_LATENCY, &customs));

    customs.clear();

    // ACK
    let flow = flows.next().unwrap();
    decoders.decode(classify.find(&flow), &flow, &mut customs);

    assert_eq!(Some(Value::from(2)), value(DHCP_OP, &customs));
    assert_eq!(Some(Value::from(5)), value(DHCP_MSG_TYPE, &customs));
    assert_eq!(Some(noaddr),         value(DHCP_CI_ADDR, &customs));
    assert_eq!(Some(yiaddr),         value(DHCP_YI_ADDR, &customs));
    assert_eq!(Some(siaddr),         value(DHCP_SI_ADDR, &customs));
    assert_eq!(Some(mac.clone()),    value(DHCP_CH_ADDR, &customs));
    assert_eq!(Some(host.clone()),   value(DHCP_HOSTNAME, &customs));
    assert_eq!(Some(domain.clone()), value(DHCP_DOMAIN, &customs));
    assert_eq!(Some(lease.clone()),  value(DHCP_LEASE, &customs));
    assert_eq!(Some(Value::from(1)), value(APP_LATENCY, &customs));
}


#[test]
fn decode_http() {
    let mut customs  = Customs::new(&CUSTOMS);
    let mut classify = Classify::new();
    let mut decoders = Decoders::new(&customs, &mut classify, true);

    let mut req_url:    Option<Value> = None;
    let mut req_host:   Option<Value> = None;
    let mut req_ua:     Option<Value> = None;
    let mut res_status: Option<Value> = None;
    let mut latency:    Option<Value> = None;

    for flow in iter::flows("pcaps/http/google.com.pcap") {
        let d = classify.find(&flow);
        decoders.decode(d, &flow, &mut customs);

        req_url    = value(HTTP_URL, &customs).or_else(|| req_url);
        req_host   = value(HTTP_HOST, &customs).or_else(|| req_host);
        req_ua     = value(HTTP_UA, &customs).or_else(|| req_ua);
        res_status = value(HTTP_STATUS, &customs).or_else(|| res_status);
        latency    = value(APP_LATENCY, &customs).or_else(|| latency);

        customs.clear();
    }

    assert_eq!(Some(Value::from("/")), req_url);
    assert_eq!(Some(Value::from("google.com")), req_host);
    assert_eq!(Some(Value::from("curl/7.38.0")), req_ua);
    assert_eq!(Some(Value::from(302)), res_status);
    assert_eq!(Some(Value::from(7)),latency);
}

#[test]
fn decode_http_dir_correct() {
    let mut customs  = Customs::new(&CUSTOMS);
    let mut classify = Classify::new();
    let mut decoders = Decoders::new(&customs, &mut classify, true);

    let mut req_host: Option<Value> = None;

    // skip the SYN packet, verify server port correct for SYNACK
    for flow in iter::flows("pcaps/http/google.com.pcap").skip(1) {
        let d = classify.find(&flow);
        decoders.decode(d, &flow, &mut customs);
        req_host = value(HTTP_HOST, &customs).or_else(|| req_host);
        customs.clear();
    }

    assert_eq!(Some(Value::from("google.com")), req_host);
}

#[test]
fn decode_http_reset_latency() {
    let mut customs  = Customs::new(&CUSTOMS);
    let mut classify = Classify::new();
    let mut decoders = Decoders::new(&customs, &mut classify, true);

    let mut latency: Option<Value> = None;

    for i in 0..2 {
        let extra = Duration::seconds(i * 2);
        for mut flow in iter::flows("pcaps/http/google.com.pcap") {
            let d = classify.find(&flow);

            flow.timestamp = flow.timestamp + extra;
            decoders.decode(d, &flow, &mut customs);
            latency = value(APP_LATENCY, &customs).or_else(|| latency);

            customs.clear();
        }
        assert_eq!(Some(Value::from(7)),latency);
    }
}

#[test]
fn decode_http_1_0_fin_data() {
    let mut customs  = Customs::new(&CUSTOMS);
    let mut classify = Classify::new();
    let mut decoders = Decoders::new(&customs, &mut classify, true);

    let mut res_status: Option<Value> = None;

    for flow in iter::flows("pcaps/http/http-1.0-fin-data.pcap") {
        let d = classify.find(&flow);
        decoders.decode(d, &flow, &mut customs);
        res_status = value(HTTP_STATUS, &customs).or_else(|| res_status);
        customs.clear();
    }

    assert_eq!(Some(Value::from(200)), res_status);
}

#[test]
fn decode_dns() {
    let mut customs  = Customs::new(&CUSTOMS);
    let mut classify = Classify::new();
    let mut decoders = Decoders::new(&customs, &mut classify, true);

    let mut query_name: Option<Value> = None;
    let mut query_type: Option<Value> = None;
    let mut reply_code: Option<Value> = None;
    let mut reply_data: Option<Value> = None;
    let mut latency:    Option<Value> = None;

    for flow in iter::flows("pcaps/dns/google.com-any.pcap").take(2) {
        let d = classify.find(&flow);
        decoders.decode(d, &flow, &mut customs);

        query_name = value(DNS_QUERY_NAME, &customs).or_else(|| query_name);
        query_type = value(DNS_QUERY_TYPE, &customs).or_else(|| query_type);
        reply_code = value(DNS_REPLY_CODE, &customs).or_else(|| reply_code);
        reply_data = value(DNS_REPLY_DATA, &customs).or_else(|| reply_data);
        latency    = value(APP_LATENCY, &customs).or_else(|| latency);

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
    let mut customs  = Customs::new(&CUSTOMS);
    let mut classify = Classify::new();
    let mut decoders = Decoders::new(&customs, &mut classify, true);

    let mut server_name:  Option<Value> = None;
    let mut server_ver:   Option<Value> = None;
    let mut cipher_suite: Option<Value> = None;

    for flow in iter::flows("pcaps/tls/google.com-tls-1.2.pcap") {
        let key = flow.key();

        let d = classify.find(&flow);
        decoders.decode(d, &flow, &mut customs);
        decoders.append(d, &key,  &mut customs);

        server_name  = value(TLS_SERVER_NAME, &customs).or_else(|| server_name);
        server_ver   = value(TLS_SERVER_VERSION, &customs).or_else(|| server_ver);
        cipher_suite = value(TLS_CIPHER_SUITE, &customs).or_else(|| cipher_suite);

        customs.clear();
    }

    assert_eq!(Some(Value::from("google.com")), server_name);
    assert_eq!(Some(Value::from(0x0303)), server_ver);
    assert_eq!(Some(Value::from(0xc02b)), cipher_suite);
}

#[test]
fn decode_tls_ignore_established() {
    let mut customs  = Customs::new(&CUSTOMS);
    let mut classify = Classify::new();
    let mut decoders = Decoders::new(&customs, &mut classify, true);

    for flow in iter::flows("pcaps/tls/google.com-tls-1.2.pcap").skip(2) {
        let key = flow.key();

        let d = classify.find(&flow);
        decoders.decode(d, &flow, &mut customs);
        decoders.append(d, &key,  &mut customs);
    }

    assert_eq!(0, customs.len());
}

#[test]
fn classify_ok() {
    let mut classify = Classify::new();
    classify.add(Protocol::UDP, 53, Decoder::DNS);
    classify.add(Protocol::TCP, 80, Decoder::HTTP);
    classify.add(Protocol::TCP, 22, Decoder::TLS);

    let mut dns_flow = flow(0, 53, false);
    dns_flow.protocol = Protocol::UDP;

    let http_flow = flow(0, 80, false);
    let tls_flow  = flow(0, 22, false);
    let none_flow = flow(0, 33, false);

    assert_eq!(Decoder::DNS,  classify.find(&dns_flow));
    assert_eq!(Decoder::HTTP, classify.find(&http_flow));
    assert_eq!(Decoder::TLS,  classify.find(&tls_flow));
    assert_eq!(Decoder::None, classify.find(&none_flow));
}

#[test]
fn app_protocol_ok() {
    let mut customs = Customs::new(&CUSTOMS);

    let specs = &[
        (Protocol::UDP, 53,  Decoder::DNS,  Value::from(1)),
        (Protocol::TCP, 80,  Decoder::HTTP, Value::from(2)),
        (Protocol::TCP, 443, Decoder::TLS,  Value::from(3)),
    ];

    for &(protocol, port, decoder, ref app_proto) in specs {
        let mut flow = flow(0, port, false);
        flow.protocol = protocol;

        customs.append(&Counter{
            ethernet:  flow.ethernet,
            direction: flow.direction,
            tos:       flow.tos,
            tcp_flags: flow.tcp_flags(),
            bytes:     flow.bytes as u64,
            packets:   flow.packets as u64,
            fragments: flow.fragments as u64,
            decoder:   decoder,
            export:    Timestamp::zero(),
        });

        assert_eq!(Some(app_proto), value(APP_PROTOCOL, &customs).as_ref());

        customs.clear();
    }
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
