use std::ascii::AsciiExt;
use std::collections::VecDeque;
use std::ffi::CString;
use std::slice;
use flow::Timestamp;
use time::Duration;
use protocol::buf::Buffer;
use http_muncher::{Parser, ParserHandler};

pub struct Connection {
    req_state: ReqState,
    res_state: ResState,
    pending:   VecDeque<Req>,
}

#[derive(Debug)]
pub struct Req {
    pub url:      Option<CString>,
    pub host:     Option<CString>,
    pub referer:  Option<CString>,
    pub ua:       Option<CString>,
    pub ts:       Timestamp,
}

#[derive(Debug)]
pub struct Res {
    pub status:   u16,
    pub url:      Option<CString>,
    pub host:     Option<CString>,
    pub referer:  Option<CString>,
    pub ua:       Option<CString>,
    pub latency:  Duration,
}

struct ReqState {
    buffer: Buffer,
    parser: Parser,
    ts:     Option<Timestamp>,
    state:  State,
}

struct ResState {
    buffer: Buffer,
    parser: Parser,
    state:  State,
}

#[derive(Debug, Default)]
struct State {
    url:      Option<CString>,
    host:     Option<CString>,
    referer:  Option<CString>,
    ua:       Option<CString>,
    status:   u16,
    header:   Option<Header>,
    complete: bool,
}

#[derive(Debug)]
enum Header {
    Host,
    Referer,
    UserAgent,
}

type Result<T> = ::std::result::Result<Option<T>, String>;

impl Connection {
    pub fn new() -> Self {
        Connection {
            req_state: ReqState::new(),
            res_state: ResState::new(),
            pending:   VecDeque::new(),
        }
    }

    pub fn parse_req(&mut self, ts: Timestamp, buf: &[u8]) -> Option<&Req> {
        self.req_state.parse(buf, ts).unwrap_or_else(|_err| {
            //println!("parse_req: error {}", err);
            self.req_state.buffer.clear();
            self.pending.clear();
            None
        }).and_then(move |req| {
            self.pending.push_back(req);
            self.pending.back()
        })
    }

    pub fn parse_res(&mut self, ts: Timestamp, buf: &[u8]) -> Option<Res> {
        self.res_state.parse(buf).unwrap_or_else(|_err| {
            //println!("parse_res: error {}", err);
            self.req_state.buffer.clear();
            self.res_state.buffer.clear();
            self.pending.clear();
            None
        }).and_then(|status| {
            self.pending.pop_front().map(move |req| {
                let latency = ts.timespec() - req.ts.timespec();
                Res{
                    status:  status,
                    url:     req.url,
                    host:    req.host,
                    referer: req.referer,
                    ua:      req.ua,
                    latency: latency,
                }
            })
        })
    }

    pub fn is_idle(&self) -> bool {
        self.req_state.is_idle() && self.res_state.is_idle() && self.pending.is_empty()
    }
}

impl ReqState {
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
            parser: Parser::request(),
            ts:     None,
            state:  Default::default(),
        }
    }

    pub fn parse(&mut self, buf: &[u8], ts: Timestamp) -> Result<Req> {
        let mut buf = self.buffer.buf(buf);
        let mut len = buf.len();
        let mut req = None;

        if self.ts.is_none() && len > 0 {
            self.ts = Some(ts);
        }

        len = len.saturating_sub(self.parser.parse(&mut self.state, &buf[..]));
        if self.parser.has_error() {
            buf.keep(0);
            return Err(error(&self.parser))
        }
        buf.keep(len);

        if self.state.complete {
            req = Some(Req{
                url:     self.state.url.take(),
                host:    self.state.host.take(),
                referer: self.state.referer.take(),
                ua:      self.state.ua.take(),
                ts:      self.ts.unwrap(),
            });
            self.state.complete = false;
            self.parser = Parser::request();
        }
        //println!("req buffer {:p} currently {:?} bytes", &buf, buf.len());

        Ok(req)
    }

    fn is_idle(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl ResState {
    pub fn new() -> Self {
        Self {
            buffer: Buffer::new(),
            parser: Parser::response(),
            state:  Default::default(),
        }
    }

    pub fn parse(&mut self, buf: &[u8]) -> Result<u16> {
        let mut buf = self.buffer.buf(buf);
        let mut len = buf.len();
        let mut res = None;

        len = len.saturating_sub(self.parser.parse(&mut self.state, &buf[..]));
        if self.parser.has_error() {
            buf.keep(0);
            return Err(error(&self.parser))
        }
        buf.keep(len);

        if self.state.complete {
            res = Some(self.parser.status_code());
            self.state.complete = false;
            self.parser = Parser::response();
        }
        //println!("res buffer {:p} currently {:?} bytes", &buf, buf.len());

        Ok(res)
    }

    fn is_idle(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl ParserHandler for State {
    fn on_url(&mut self, _: &mut Parser, url: &[u8]) -> bool {
        self.url = CString::new(url).ok();
        true
    }

    // FIXME: name might be partial, collect in vec
    fn on_header_field(&mut self, _: &mut Parser, name: &[u8]) -> bool {
        let name = unsafe {
            let s = slice::from_raw_parts_mut(name.as_ptr() as *mut u8, name.len());
            s.make_ascii_lowercase();
            &s[..]
        };

        self.header = match name {
            b"host"       => Some(Header::Host),
            b"referer"    => Some(Header::Referer),
            b"user-agent" => Some(Header::UserAgent),
            _             => None
        };

        true
    }

    // FIXME: value might be partial, collect in vec
    fn on_header_value(&mut self, _: &mut Parser, value: &[u8]) -> bool {
        match self.header {
            Some(Header::Host)      => self.host = CString::new(value).ok(),
            Some(Header::Referer)   => self.referer = CString::new(value).ok(),
            Some(Header::UserAgent) => self.ua = CString::new(value).ok(),
            _                       => (),
        };
        true
    }

    fn on_message_complete(&mut self, _: &mut Parser) -> bool {
        self.complete = true;
        true
    }
}

fn error(p: &Parser) -> String {
    format!("{} {}", p.error(), p.error_description())
}
