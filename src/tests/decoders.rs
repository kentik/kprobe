use custom::Customs;
use protocol::Decoders;
use super::*;

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
