use std::ffi::CString;
use super::conn::*;
use crate::time::Timestamp;
use libc::timeval;
use time::Duration;

#[test]
fn test_decode() {
    let mut c = Connection::new(80);

    {
        let b = b"GET / HTTP/1.1\r\n\r\n";
        let r = c.parse_req(ts(), b).unwrap();
        assert_eq!(Some(cstr("/")), r.url);
    }

    {
        let b = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
        let r = c.parse_res(ts(), &b).unwrap();
        assert_eq!(200, r.status);
        assert_eq!(Some(cstr("/")), r.url);
    }
}

#[test]
fn test_decode_invalid_req() {
    let mut c = Connection::new(80);

    {
        let b = b"FOO\r\n\r\n";
        let r = c.parse_req(ts(), b);
        assert!(r.is_none());
    }
}

#[test]
fn test_decode_invalid_res() {
    let mut c = Connection::new(80);

    {
        let b = b"GET / HTTP/1.1\r\n\r\n";
        let r = c.parse_req(ts(), b);
        assert!(r.is_some());
    }

    {
        let b = b"FOO\r\n\r\n";
        let r = c.parse_res(ts(), b);
        assert!(r.is_none());
    }
}

#[test]
fn test_header_case_insensitive() {
    for h in vec!["User-Agent", "USER-AGENT", "user-agent"] {
        let mut c = Connection::new(80);
        let b = format!("GET / HTTP/1.1\r\n{}: foo\r\n\r\n", h);
        let r = c.parse_req(ts(), &b.into_bytes()).unwrap();
        assert_eq!(Some(cstr("foo")), r.ua);
    }
}

#[test]
fn test_is_idle() {
    let timeout = Duration::seconds(15);
    let now     = Timestamp::now();

    let mut c = Connection::new(80);
    let b = b"GET / HTTP/1.1\r\n\r\n";
    c.parse_req(now, b);

    assert_eq!(false, c.is_idle(now + Duration::seconds(10), timeout));
    assert_eq!(true,  c.is_idle(now + Duration::seconds(16), timeout));
}

fn ts() -> Timestamp {
    Timestamp::from(timeval{
        tv_sec:  0,
        tv_usec: 0,
    })
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}
