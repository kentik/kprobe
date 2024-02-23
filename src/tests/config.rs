use std::ffi::{CString};
use pnet::datalink::NetworkInterface;
use crate::args::{Args, parser};
use crate::libkflow::*;

#[test]
fn test_default_urls() {
    let cfg = Config::new(&interface(), None, 0, false);
    assert_eq!(cstr("https://api.kentik.com/api/internal"), cfg.api.url);
    assert_eq!(cstr("https://flow.kentik.com/chf"), cfg.url);
    assert_eq!(cstr("https://flow.kentik.com/tsdb"), cfg.metrics.url);
    assert_eq!(cstr("https://flow.kentik.com/dns"), cfg.dns.url);
}

#[test]
fn test_us_region_urls() {
    let cfg = Config::new(&interface(), Some("US".to_owned()), 0, false);
    assert_eq!(cstr("https://api.kentik.com/api/internal"), cfg.api.url);
    assert_eq!(cstr("https://flow.kentik.com/chf"), cfg.url);
    assert_eq!(cstr("https://flow.kentik.com/tsdb"), cfg.metrics.url);
    assert_eq!(cstr("https://flow.kentik.com/dns"), cfg.dns.url);
}

#[test]
fn test_eu_region_urls() {
    let cfg = Config::new(&interface(), Some("EU".to_owned()), 0, false);
    assert_eq!(cstr("https://api.kentik.eu/api/internal"), cfg.api.url);
    assert_eq!(cstr("https://flow.kentik.eu/chf"), cfg.url);
    assert_eq!(cstr("https://flow.kentik.eu/tsdb"), cfg.metrics.url);
    assert_eq!(cstr("https://flow.kentik.eu/dns"), cfg.dns.url);
}

#[test]
fn test_jp1_region_urls() {
    let cfg = Config::new(&interface(), Some("jp1".to_owned()), 0, false);
    assert_eq!(cstr("https://api.jp1.kentik.com/api/internal"), cfg.api.url);
    assert_eq!(cstr("https://flow.jp1.kentik.com/chf"), cfg.url);
    assert_eq!(cstr("https://flow.jp1.kentik.com/tsdb"), cfg.metrics.url);
    assert_eq!(cstr("https://flow.jp1.kentik.com/dns"), cfg.dns.url);
}

#[test]
fn test_region_case_insensitivity() {
    for region in &["us", "uS", "US"] {
        let reg = Some(region.to_string());
        let cfg = Config::new(&interface(), reg, 0, false);
        assert_eq!(cstr("https://flow.kentik.com/chf"), cfg.url)
    }
}

#[test]
fn test_http_config() {
    let args = parse(&[
        "--email",  "test@example.com",
        "--token",  "asdf1234",
    ]);

    let config = args.http_config().unwrap();

    assert_eq!("test@example.com", config.0);
    assert_eq!("asdf1234",         config.1);
    assert_eq!(None,               config.2);
}

#[test]
fn test_http_config_with_proxy() {
    let args = parse(&[
        "--email",     "test@example.com",
        "--token",     "asdf1234",
        "--proxy-url", "http://proxy:1234",
    ]);

    let config = args.http_config().unwrap();

    assert_eq!(Some("http://proxy:1234".into()), config.2);
}

fn cstr(str: &str) -> CString {
    CString::new(str).unwrap()
}

fn interface() -> NetworkInterface {
    NetworkInterface {
        name:  "test".to_owned(),
        index: 1,
        mac:   None,
        ips:   Vec::new(),
        flags: 0,
        description: "".to_owned(),
    }
}

fn parse(args: &[&str]) -> Args {
    let mut vec = vec!["-i", "lo"];
    vec.extend_from_slice(args);
    let args = bpaf::Args::from(&vec[..]);
    parser().run_inner(args).unwrap()
}
