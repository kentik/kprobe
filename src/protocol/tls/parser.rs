use std::ffi::CString;
use nom::*;
use nom::IResult::*;
use byteorder::{ByteOrder, BigEndian as BE};

#[derive(Debug)]
pub enum Record {
    Hello(Hello),
    Other(u8),
    Unsupported(Version),
}

#[derive(Debug)]
pub enum Hello {
    Client(Version, Option<CString>),
    Server(Version, CipherSuite),
    Done,
    Other(u8),
}

#[derive(Copy, Clone, Debug)]
pub struct Version(u8, u8);

#[derive(Debug)]
pub struct CipherSuite(u16);

#[derive(Debug)]
pub enum Extension {
    SNI(Vec<ServerName>),
    Other(u16),
}

#[derive(Debug)]
pub enum ServerName {
    HostName(CString),
    Other(u8, CString),
}

named!(pub parse_records<&[u8], Vec<Record>>, many1!(record));

// TODO: this only correctly handles plaintext records
pub fn record(buf: &[u8]) -> IResult<&[u8], Record> {
    if buf.len() < 5 {
        return Incomplete(Needed::Size(5))
    }

    let ctype = buf[0];
    let ver   = BE::read_u16(&buf[1..3]);
    let len   = BE::read_u16(&buf[3..5]) as usize;
    let rest  = &buf[5..];

    if rest.len() < len {
        return Incomplete(Needed::Size(len - rest.len()));
    }

    if ver < 0x0301 {
        let major = (ver >> 8) as u8;
        let minor = (ver & 0xFF) as u8;
        let v = Version(major, minor);
        return Done(&rest[len..], Record::Unsupported(v));
    }

    match ctype {
        0x16 => handshake(rest),
        n    => Done(&rest[len..], Record::Other(n)),
    }
}

pub fn handshake(buf: &[u8]) -> IResult<&[u8], Record> {
    if buf.len() < 4 {
        return Incomplete(Needed::Size(4));
    }

    let n32   = BE::read_u32(&buf[0..4]);
    let htype = (n32 >> 24) as u8;
    let len   = (n32 & 0xFFFFFF) as usize;
    let rest  = &buf[4..];

    if rest.len() < len {
        return Incomplete(Needed::Size(len - rest.len()));
    }

    match htype {
        0x01 => client_hello(rest),
        0x02 => server_hello(rest),
        0x0e => Done(&rest[len..], Hello::Done),
        n    => Done(&rest[len..], Hello::Other(n)),
    }.map(Record::Hello)
}

named!(client_hello<&[u8], Hello>, do_parse!(
    major:          be_u8
 >> minor:          be_u8
 >> _gmt_unix_time: be_u32
 >> _random_bytes:  take!(28)
 >> _session_id:    length_bytes!(be_u8)
 >> _cipher_suites: length_bytes!(be_u16)
 >> _compression:   length_bytes!(be_u8)
 >> extensions:     flat_map!(length_bytes!(be_u16), many0!(extension))
 >> (Hello::Client(Version(major, minor), find_sni(extensions)))
));

named!(server_hello<&[u8], Hello>, do_parse!(
    major:          be_u8
 >> minor:          be_u8
 >> _gmt_unix_time: be_u32
 >> _random_bytes:  take!(28)
 >> _session_id:    length_bytes!(be_u8)
 >> cipher_suite:   be_u16
 >> _compression:   be_u8
 >> extensions:     flat_map!(length_bytes!(be_u16), many0!(extension))
 >> (Hello::Server(Version(major, minor), CipherSuite(cipher_suite)))
));

fn extension(buf: &[u8]) -> IResult<&[u8], Extension> {
    if buf.len() < 4 {
        return Incomplete(Needed::Size(4))
    }

    let etype = BE::read_u16(&buf[0..2]);
    let len   = BE::read_u16(&buf[2..4]) as usize;
    let rest  = &buf[4..];

    if rest.len() < len {
        return Incomplete(Needed::Size(len - rest.len()));
    }

    match etype {
        0x0000 if len > 0 => server_names(rest),
        0x0000            => Done(&rest[len..], Extension::SNI(Vec::new())),
        n                 => Done(&rest[len..], Extension::Other(n)),
    }
}

named!(server_names<&[u8], Extension>, do_parse!(
    names: flat_map!(length_bytes!(be_u16), many0!(server_name))
 >> (Extension::SNI(names))
));

named!(server_name<&[u8], ServerName>, do_parse!(
    ntype: be_u8
 >> len:   be_u16
 >> name:  map_res!(take_str!(len), CString::new)
 >> (match ntype {
         0 => ServerName::HostName(name),
         n => ServerName::Other(n, name),
    })
));

fn find_sni(es: Vec<Extension>) -> Option<CString> {
    es.into_iter().flat_map(|e| match e {
        Extension::SNI(ns) => find_host_name(ns),
        _                  => None,
    }).next()
}

fn find_host_name(ns: Vec<ServerName>) -> Option<CString> {
    ns.into_iter().flat_map(|n| match n {
        ServerName::HostName(n) => Some(n),
        _                       => None,
    }).next()
}
