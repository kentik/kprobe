use std::net::Ipv4Addr;
use std::ffi::{CStr, FromBytesWithNulError};
use std::str;
use nom::*;

#[derive(Debug)]
pub struct Message<'a> {
    pub op:     u8,
    pub htype:  u8,
    pub hops:   u8,
    pub xid:    u32,
    pub secs:   u16,
    pub flags:  u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: &'a [u8],
    pub sname:  &'a CStr,
    pub file:   &'a CStr,
    pub opts:   Vec<Opt<'a>>
}

#[derive(Debug)]
pub enum Opt<'a> {
    Type(u8),
    Host(&'a str),
    Domain(&'a str),
    Lease(u32),
    Params(&'a [u8]),
    Other(u8, &'a [u8]),
}

named!(pub message<&[u8], Message>, do_parse!(
    op:     be_u8
 >> htype:  be_u8
 >> hlen:   map!(be_u8, usize::from)
 >> hops:   be_u8
 >> xid:    be_u32
 >> secs:   be_u16
 >> flags:  be_u16
 >> ciaddr: map!(be_u32, Ipv4Addr::from)
 >> yiaddr: map!(be_u32, Ipv4Addr::from)
 >> siaddr: map!(be_u32, Ipv4Addr::from)
 >> giaddr: map!(be_u32, Ipv4Addr::from)
 >> chaddr: take!(16)
 >> sname:  map_res!(take!(64), cstr)
 >> file:   map_res!(take!(128), cstr)
 >> magic:  tag!(&[0x63, 0x82, 0x53, 0x63])
 >> opts:   fold_many0!(opts, Vec::new(), collect)
 >> (Message{
     op:     op,
     htype:  htype,
     hops:   hops,
     xid:    xid,
     secs:   secs,
     flags:  flags,
     ciaddr: ciaddr,
     yiaddr: yiaddr,
     siaddr: siaddr,
     giaddr: giaddr,
     chaddr: &chaddr[..hlen],
     sname:  sname,
     file:   file,
     opts:   opts,
    })
));

named!(opts<&[u8], Option<Opt>>, alt!(
    opt_host   |
    opt_domain |
    opt_lease  |
    opt_type   |
    opt_params |
    opt_pad    |
    opt_end    |
    opt_other
));

named!(opt_host<&[u8], Option<Opt>>, do_parse!(
    tag!(&[0x0C])
 >> name: map_res!(length_bytes!(be_u8), str::from_utf8)
 >> (Some(Opt::Host(name)))
));

named!(opt_domain<&[u8], Option<Opt>>, do_parse!(
    tag!(&[0x0F])
 >> name: map_res!(length_bytes!(be_u8), str::from_utf8)
 >> (Some(Opt::Domain(name)))
));

named!(opt_lease<&[u8], Option<Opt>>, do_parse!(
    tag!(&[0x33, 0x04])
 >> secs: be_u32
 >> (Some(Opt::Lease(secs)))
));

named!(opt_type<&[u8], Option<Opt>>, do_parse!(
    tag!(&[0x35, 0x01])
 >> code: be_u8
 >> (Some(Opt::Type(code)))
));

named!(opt_params<&[u8], Option<Opt>>, do_parse!(
    tag!(&[0x37])
 >> data: length_bytes!(be_u8)
 >> (Some(Opt::Params(data)))
));

named!(opt_pad<&[u8], Option<Opt>>, do_parse!(tag!(&[0x00]) >> (None)));
named!(opt_end<&[u8], Option<Opt>>, do_parse!(tag!(&[0xFF]) >> (None)));

named!(opt_other<&[u8], Option<Opt>>, do_parse!(
    code: be_u8
 >> data: length_bytes!(be_u8)
 >> (Some(Opt::Other(code, data)))
));

fn cstr(buf: &[u8]) -> Result<&CStr, FromBytesWithNulError>  {
    match buf[0] {
        0 => CStr::from_bytes_with_nul(&buf[..1]),
        _ => CStr::from_bytes_with_nul(&buf),
    }
}

fn collect<'a>(mut vec: Vec<Opt<'a>>, o: Option<Opt<'a>>) -> Vec<Opt<'a>> {
    if let Some(o) = o {
        vec.push(o);
    }
    vec
}
