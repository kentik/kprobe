use std::ffi::CString;
use super::conn::*;
use flow::Timestamp;
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

    assert_eq!(true, c.is_idle(Timestamp::zero(), Duration::seconds(1)));
}

#[test]
fn test_decode_invalid_req() {
    let mut c = Connection::new(80);

    {
        let b = b"FOO\r\n\r\n";
        let r = c.parse_req(ts(), b);
        assert!(r.is_none());
    }

    assert_eq!(true, c.is_idle(Timestamp::zero(), Duration::seconds(1)));
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

    assert_eq!(true, c.is_idle(Timestamp::zero(), Duration::seconds(1)));
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

fn ts() -> Timestamp {
    Timestamp(timeval{
        tv_sec:  0,
        tv_usec: 0,
    })
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}
