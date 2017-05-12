#![allow(unused_variables)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;
use nom::*;
use nom::IResult::Done;

#[derive(Debug)]
pub struct Message<'a> {
    pub header:     Header,
    pub query:      Vec<QQ>,
    pub answer:     Vec<RR<'a>>,
    pub authority:  Vec<RR<'a>>,
    pub additional: Vec<RR<'a>>,
}

#[derive(Debug)]
pub struct Header {
    pub id:      u16,
    pub qr:      u8,
    pub opcode:  u8,
    pub aa:      bool,
    pub tc:      bool,
    pub rd:      bool,
    pub ra:      bool,
    pub rcode:   u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug)]
pub struct QQ {
    pub qname:  String,
    pub qtype:  u16,
    pub qclass: u16,
}

#[derive(Debug)]
pub struct RR<'a> {
    pub name:  String,
    pub rtype: u16,
    pub class: u16,
    pub ttl:   u32,
    pub rdata: Rdata<'a>
}

#[derive(Debug)]
pub enum Rdata<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ptr(String),
    Mx(u16, String),
    Ns(String),
    Txt(Vec<&'a str>),
    Other(&'a [u8]),

    Soa {
        mname:   String,
        rname:   String,
        serial:  u32,
        refresh: u32,
        retry:   u32,
        expire:  u32,
        minimum: u32,
    },
}

pub fn parse_message(buf: &[u8]) -> IResult<&[u8], Message> {
    message(buf, buf)
}

named_args!(message<'a>(msg: &'a [u8]) <Message<'a>>, do_parse!(
    header:     header
 >> query:      count!(call!(qq, msg), header.qdcount as usize)
 >> answer:     count!(call!(rr, msg), header.ancount as usize)
 >> authority:  count!(call!(rr, msg), header.nscount as usize)
 >> additional: count!(call!(rr, msg), header.arcount as usize)
 >> (Message {
     header:     header,
     query:      query,
     answer:     answer,
     authority:  authority,
     additional: additional,
 })
));

named!(header<&[u8], Header>, do_parse!(
    id:      be_u16
 >> bits:    bits!(tuple!(
     take_bits!(u8, 1),
     take_bits!(u8, 4),
     take_bits!(u8, 1),
     take_bits!(u8, 1),
     take_bits!(u8, 1),
     take_bits!(u8, 1),
     take_bits!(u8, 3),
     take_bits!(u8, 4)))
 >> qdcount: be_u16
 >> ancount: be_u16
 >> nscount: be_u16
 >> arcount: be_u16
 >> (Header {
     id:      id,
     qr:      bits.0,
     opcode:  bits.1,
     aa:      bits.2 == 1,
     tc:      bits.3 == 1,
     rd:      bits.4 == 1,
     ra:      bits.5 == 1,
     rcode:   bits.7,
     qdcount: qdcount,
     ancount: ancount,
     nscount: nscount,
     arcount: arcount,
  })
));

named_args!(qq<'a>(msg: &'a [u8]) <QQ>, do_parse!(
    qname:  call!(name, msg)
 >> qtype:  be_u16
 >> qclass: be_u16
 >> (QQ {
     qname:  qname,
     qtype:  qtype,
     qclass: qclass,
 })
));

named_args!(rr<'a>(msg: &'a [u8]) <RR<'a>>, do_parse!(
    name:     call!(name, msg)
 >> rtype:    be_u16
 >> class:    be_u16
 >> ttl:      be_u32
 >> rdata:    call!(rdata, msg, rtype)
 >> (RR {
     name:  name,
     rtype: rtype,
     class: class,
     ttl:   ttl,
     rdata: rdata,
 })
));

fn rdata<'a>(buf: &'a [u8], msg: &'a [u8], rtype: u16) -> IResult<&'a [u8], Rdata<'a>> {
    match rtype {
        1  => rdata_a(buf),
        2  => rdata_ns(buf, msg),
        5  => rdata_cname(buf, msg),
        6  => rdata_soa(buf, msg),
        12 => rdata_ptr(buf, msg),
        15 => rdata_mx(buf, msg),
        16 => rdata_txt(buf),
        28 => rdata_aaaa(buf),
        _  => rdata_other(buf)
    }
}

named_args!(rdata_a<'a>() <Rdata<'a>>, do_parse!(
    verify!(be_u16, |n: u16| n == 4)
 >> ip: map!(be_u32, Ipv4Addr::from)
 >> (Rdata::A(ip))
));

named_args!(rdata_aaaa<'a>() <Rdata<'a>>, do_parse!(
    verify!(be_u16, |n: u16| n == 16)
 >> ip: map!(take!(16), parse_ipv6)
 >> (Rdata::Aaaa(ip))
));

named_args!(rdata_ns<'a>(msg: &'a [u8]) <Rdata<'a>>,
    map!(call!(rdata_name, msg), Rdata::Ns)
);

named_args!(rdata_cname<'a>(msg: &'a [u8]) <Rdata<'a>>,
    map!(call!(rdata_name, msg), Rdata::Cname)
);

named_args!(rdata_ptr<'a>(msg: &'a [u8]) <Rdata<'a>>,
    map!(call!(rdata_name, msg), Rdata::Ptr)
);

named_args!(rdata_txt<'a>() <Rdata<'a>>, do_parse!(
    len: be_u16
 >> txt: flat_map!(take!(len), many1!(char_str))
 >> (Rdata::Txt(txt))
));

named_args!(rdata_mx<'a>(msg: &'a [u8]) <Rdata<'a>>, do_parse!(
    be_u16
 >> pref: be_u16
 >> ex:   call!(name, msg)
 >> (Rdata::Mx(pref, ex))
));

named_args!(rdata_soa<'a>(msg: &'a [u8]) <Rdata<'a>>, do_parse!(
    be_u16
 >> mname:   call!(name, msg)
 >> rname:   call!(name, msg)
 >> serial:  be_u32
 >> refresh: be_u32
 >> retry:   be_u32
 >> expire:  be_u32
 >> minimum: be_u32
 >> (Rdata::Soa {
     mname:   mname,
     rname:   rname,
     serial:  serial,
     refresh: refresh,
     retry:   retry,
     expire:  expire,
     minimum: minimum,
 })
));

named_args!(rdata_other<'a>() <Rdata<'a>>, do_parse!(
    len: be_u16
 >> buf: take!(len)
 >> (Rdata::Other(buf))
));

named_args!(rdata_name<'a>(msg: &'a [u8]) <String>, do_parse!(
    len: be_u16
 >> str: flat_map!(take!(len), call!(name, msg))
 >> (str)
));

named!(char_str<&[u8], &str>, map_res!(length_bytes!(be_u8), str::from_utf8));

named_args!(name<'a>(msg: &'a [u8]) <String>, map_res!(alt!(
    do_parse!(peek!(bits!(len_tag)) >> vec: call!(string,  msg, Vec::with_capacity(64)) >> (vec)) |
    do_parse!(peek!(bits!(ptr_tag)) >> vec: call!(pointer, msg, Vec::with_capacity(64)) >> (vec))
    ), String::from_utf8)
);

named_args!(string<'a>(msg: &'a [u8], vec: Vec<u8>) <Vec<u8>>, do_parse!(
    tup: call!(labels, vec)
 >> vec: call!(endofs, msg, tup.1)
 >> (vec)
));

named_args!(pointer<'a>(msg: &'a [u8], vec: Vec<u8>) <Vec<u8>>, do_parse!(
    off: bits!(ptr_offset)
 >> vec: call!(resolve_ptr, msg, off, vec)
 >> (vec)
));

named_args!(labels<'a>(vec: Vec<u8>) <(bool, Vec<u8>)>,
    fold_many0!(label, (vec.is_empty(), vec), |mut args: (bool, Vec<u8>), name| {
        if !args.0 {
            args.1.push(b'.');
        }
        args.1.extend_from_slice(name);
        (false, args.1)
    })
);

named!(label<&[u8], &[u8]>, do_parse!(
    len:   verify!(bits!(label_len), |n: u8| n > 0)
 >> label: take!(len)
 >> (label)
));

named!(label_len<(&[u8], usize), u8>, do_parse!(
    len_tag
 >> len: take_bits!(u8, 6)
 >> (len)
));

named!(ptr_offset<(&[u8], usize), usize>, do_parse!(
    ptr_tag
 >> off: take_bits!(u16, 14)
 >> (off as usize)
));

named!(len_tag<(&[u8], usize), u8>, tag_bits!(u8, 2, 0b00));
named!(ptr_tag<(&[u8], usize), u8>, tag_bits!(u8, 2, 0b11));

named_args!(endofs<'a>(msg: &'a [u8], vec: Vec<u8>) <Vec<u8>>,
    switch!(peek!(be_u8),
        0 => do_parse!(take!(1) >> (vec)) |
        _ => call!(pointer, msg, vec)
    )
);

fn resolve_ptr<'a>(buf: &'a [u8], msg: &'a [u8], ptr: usize, vec: Vec<u8>) -> IResult<&'a [u8], Vec<u8>> {
    if ptr >= msg.len() {
        let needed = Needed::Size(ptr - msg.len());
        return IResult::Incomplete(needed);
    }

    match string(&msg[ptr..], msg, vec) {
        Done(_, vec) => Done(buf, vec),
        _            => Done(buf, vec![]),
    }
}

fn parse_ipv6<'a>(buf: &'a [u8]) -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    bytes.clone_from_slice(buf);
    Ipv6Addr::from(bytes)
}
