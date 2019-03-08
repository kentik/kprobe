use std::ffi::CString;
use pnet::datalink::NetworkInterface;
use libkflow::*;

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
    }
}
