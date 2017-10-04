use custom::Customs;
use protocol::{Classify, Decoder, Decoders};
use super::*;

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

    let mut server_name: Option<Value> = None;

    for flow in iter::flows("pcaps/tls/google.com-tls-1.2.pcap") {
        let key = flow.key();

        let d = classify.find(&flow);
        decoders.decode(d, &flow, &mut customs);
        decoders.append(d, &key,  &mut customs);

        server_name = value(TLS_SERVER_NAME, &customs).or_else(|| server_name);

        customs.clear();
    }

    assert_eq!(Some(Value::from("google.com")), server_name);
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
