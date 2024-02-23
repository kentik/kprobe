use crate::mode::{dns::Dns, radius};
use kentik_api::{dns, tag, AsyncClient, Client};
use super::*;

#[test]
fn dns_mode_parse() {
    let client = AsyncClient::new("test@example.com", "token", "http://127.0.0.1", None);
    let client = dns::Client::new(client.unwrap());

    let mut dns = Dns::new(client);

    let flows = iter::flows("pcaps/dns/google.com-any.pcap");
    let res   = flows.skip(1).next().unwrap();

    let packet = res.payload.to_vec();
    let result = dns.parse(res.src, res.dst, &packet);

    let expect = Some(dns::Response {
        question: dns::Question {
            name: "google.com".to_owned(),
            host: vec![10, 0, 0, 52],
        },
        answers: vec![
            dns::Answer {
                name:  String::new(),
                cname: String::new(),
                ip:    vec![172, 217, 26, 14],
                ttl:   299,
            },
            dns::Answer {
                name:  String::new(),
                cname: String::new(),
                ip:    vec![36, 4, 104, 0, 64, 4, 8, 9, 0, 0, 0, 0, 0, 0, 32, 14],
                ttl:   299,
            },
        ],
    });

    assert_eq!(expect, result);
}

#[test]
fn radius_mode_parse() {
    let client = Client::new("test@example.com", "token", "http://127.0.0.1", None);
    let client = tag::Client::new(client.unwrap());

    let mut radius = radius::Radius::new(client);

    let mut flows = iter::flows("pcaps/radius/radius-acct-start.pcap");
    let req       = flows.next().unwrap();

    let result = radius.parse(&req.payload);
    let expect = Some(radius::Request::Start(
        "bob".to_owned(),
        "10.1.2.3".parse().unwrap(),
    ));

    assert_eq!(expect, result);

    let mut flows = iter::flows("pcaps/radius/radius-acct-stop.pcap");
    let req       = flows.next().unwrap();

    let result = radius.parse(&req.payload);
    let expect = Some(radius::Request::Stop(
        "bob".to_owned(),
    ));

    assert_eq!(expect, result);
}
