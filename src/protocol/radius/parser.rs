use std::net::Ipv4Addr;
use std::str;
use nom::*;

#[derive(Debug)]
pub struct Message<'a> {
    pub code:   Code,
    pub id:     u8,
    pub auth:   &'a [u8],
    pub attrs:  Vec<Attr<'a>>
}

#[derive(Eq, PartialEq, Debug)]
pub enum Code {
    AccessRequest,
    AccessAccept,
    AccessReject,
    AccessChallenge,
    AccountingRequest,
    AccountingResponse,
    Other(u8),
}

#[derive(Debug)]
pub enum Attr<'a> {
    UserName(&'a str),
    UserPassword,
    CHAPPassword,
    ServiceType(ServiceType),
    NASIPAddr(Ipv4Addr),
    NASPort(u32),
    FramedIPAddr(Ipv4Addr),
    FramedIPMask(Ipv4Addr),
    ReplyMessage(&'a str),
    NASIdentifier(&'a [u8]),
    AcctStatusType(AcctStatusType),
    AcctSessionID(&'a str),
    Other(u8, &'a [u8]),
}

#[derive(Eq, PartialEq, Debug)]
pub enum ServiceType {
    Login,
    Framed,
    CallbackLogin,
    CallbackFramed,
    Outbound,
    Administrative,
    NASPrompt,
    AuthenticateOnly,
    CallbackNASPrompt,
    CallCheck,
    CallbackAdministrative,
    Other(u32),
}

#[derive(Eq, PartialEq, Debug)]
pub enum AcctStatusType {
    Start,
    Stop,
    InterimUpdate,
    AccountingOn,
    AccountingOff,
    Other(u32),
}

named!(pub message<&[u8], Message>, do_parse!(
    code:   call!(code)
 >> id:     be_u8
 >> _len:   map!(be_u16, usize::from)
 >> auth:   take!(16)
 >> attrs:  many0!(attrs)
 >> (Message{
     code:  code,
     id:    id,
     auth:  auth,
     attrs: attrs,
 })
));

named!(code<&[u8], Code>, switch!(be_u8,
     1 => value!(Code::AccessRequest)      |
     2 => value!(Code::AccessAccept)       |
     3 => value!(Code::AccessReject)       |
     4 => value!(Code::AccountingRequest)  |
     5 => value!(Code::AccountingResponse) |
    11 => value!(Code::AccessChallenge)    |
     n => value!(Code::Other(n))
));

named!(attrs<&[u8], Attr>, alt!(
    switch!(be_u8,
        1 => call!(attr_user_name)        |
        2 => call!(attr_user_password)    |
        3 => call!(attr_chap_password)    |
        4 => call!(attr_nas_ip_addr)      |
        5 => call!(attr_nas_port)         |
        6 => call!(attr_service_type)     |
        8 => call!(attr_framed_ip_addr)   |
        9 => call!(attr_framed_ip_mask)   |
       18 => call!(attr_reply_message)    |
       32 => call!(attr_nas_identifier)   |
       40 => call!(attr_acct_status_type) |
       44 => call!(attr_acct_session_id)
    ) | attr_other
));

named!(attr_user_name<&[u8], Attr>, do_parse!(
    len:   be_u8
 >> value: map_res!(take!(len - 2), str::from_utf8)
 >> (Attr::UserName(value))
));

named!(attr_user_password<&[u8], Attr>, do_parse!(
    len:   be_u8
 >> value: take!(len - 2)
 >> (Attr::UserPassword)
));

named!(attr_chap_password<&[u8], Attr>, do_parse!(
    _len:  verify!(be_u8, |n: u8| n == 19)
 >> ident: be_u8
 >> value: take!(16)
 >> (Attr::CHAPPassword)
));

named!(attr_nas_ip_addr<&[u8], Attr>, do_parse!(
    _len:  verify!(be_u8, |n: u8| n == 6)
 >> ip:    map!(be_u32, Ipv4Addr::from)
 >> (Attr::NASIPAddr(ip))
));

named!(attr_nas_port<&[u8], Attr>, do_parse!(
    _len:  verify!(be_u8, |n: u8| n == 6)
 >> port:  be_u32
 >> (Attr::NASPort(port))
));

named!(attr_service_type<&[u8], Attr>, do_parse!(
    _len:  verify!(be_u8, |n: u8| n == 6)
 >> kind:  switch!(be_u32,
      1 => value!(ServiceType::Login)                  |
      2 => value!(ServiceType::Framed)                 |
      3 => value!(ServiceType::CallbackLogin)          |
      4 => value!(ServiceType::CallbackFramed)         |
      5 => value!(ServiceType::Outbound)               |
      6 => value!(ServiceType::Administrative)         |
      7 => value!(ServiceType::NASPrompt)              |
      8 => value!(ServiceType::AuthenticateOnly)       |
      9 => value!(ServiceType::CallbackNASPrompt)      |
     10 => value!(ServiceType::CallCheck)              |
     11 => value!(ServiceType::CallbackAdministrative) |
      n => value!(ServiceType::Other(n))
    )
 >> (Attr::ServiceType(kind))
));

named!(attr_framed_ip_addr<&[u8], Attr>, do_parse!(
    _len:  verify!(be_u8, |n: u8| n == 6)
 >> ip:    map!(be_u32, Ipv4Addr::from)
 >> (Attr::FramedIPAddr(ip))
));

named!(attr_framed_ip_mask<&[u8], Attr>, do_parse!(
    _len:  verify!(be_u8, |n: u8| n == 6)
 >> ip:    map!(be_u32, Ipv4Addr::from)
 >> (Attr::FramedIPMask(ip))
));

named!(attr_reply_message<&[u8], Attr>, do_parse!(
    len:   be_u8
 >> msg:   map_res!(take!(len - 2), str::from_utf8)
 >> (Attr::ReplyMessage(msg))
));

named!(attr_nas_identifier<&[u8], Attr>, do_parse!(
    len:   be_u8
 >> value: take!(len - 2)
 >> (Attr::NASIdentifier(value))
));

named!(attr_acct_status_type<&[u8], Attr>, do_parse!(
    _len:  verify!(be_u8, |n: u8| n == 6)
 >> kind:  switch!(be_u32,
      1 => value!(AcctStatusType::Start)         |
      2 => value!(AcctStatusType::Stop)          |
      3 => value!(AcctStatusType::InterimUpdate) |
      4 => value!(AcctStatusType::AccountingOn)  |
      5 => value!(AcctStatusType::AccountingOff) |
      n => value!(AcctStatusType::Other(n))
    )
 >> (Attr::AcctStatusType(kind))
));

named!(attr_acct_session_id<&[u8], Attr>, do_parse!(
    len:   be_u8
 >> value: map_res!(take!(len - 2), str::from_utf8)
 >> (Attr::AcctSessionID(value))
));

named!(attr_other<&[u8], Attr>, do_parse!(
    kind:  be_u8
 >> len:   be_u8
 >> value: take!(len - 2)
 >> (Attr::Other(kind, value))
));
