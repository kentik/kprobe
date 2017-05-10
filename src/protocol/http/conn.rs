use std::collections::VecDeque;
use std::ffi::CString;
use flow::Timestamp;
use time::Duration;
use protocol::buf::Buffer;
use httparse::{self, Request, Response, Status};

pub struct Connection {
    buffer_req: Buffer,
    buffer_res: Buffer,
    state:      State,
}

struct State {
    pending: VecDeque<Req>,
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

impl Connection {
    pub fn new() -> Self {
        Connection {
            buffer_req: Buffer::new(),
            buffer_res: Buffer::new(),
            state:      State {
                pending: VecDeque::new(),
            },
        }
    }

    pub fn parse_req(&mut self, ts: Timestamp, buf: &[u8]) -> Option<&Req> {
        let state = &mut self.state;
        let mut buf = self.buffer_req.buf(buf);
        let mut completed = None;
        let mut remainder = buf.len();

        {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut request = Request::new(&mut headers);
            if let Ok(Status::Complete(n)) = request.parse(&buf[..]) {
                let url = request.path.and_then(|s| CString::new(s).ok());
                let mut host:    Option<CString> = None;
                let mut referer: Option<CString> = None;
                let mut ua:      Option<CString> = None;

                for h in request.headers {
                    match h.name {
                        "Host"       => host    = CString::new(h.value).ok(),
                        "Referer"    => referer = CString::new(h.value).ok(),
                        "User-Agent" => ua      = CString::new(h.value).ok(),
                        _            => ()
                    };
                }

                // FIXME: consume body
                state.pending.push_back(Req{
                    url:     url,
                    host:    host,
                    referer: referer,
                    ua:      ua,
                    ts:      ts,
                });

                remainder -= n;

                completed = state.pending.back();
            }
        }

        buf.keep(remainder);
        // println!("buffer {:p} currently {:?}", &buf, CString::new(&buf[..]));

        completed
    }

    pub fn parse_res(&mut self, ts: Timestamp, buf: &[u8]) -> Option<Res> {
        let state = &mut self.state;
        let mut buf = self.buffer_res.buf(buf);
        let mut completed = None;
        let mut remainder = buf.len();

        {
            let mut headers  = [httparse::EMPTY_HEADER; 16];
            let mut response = Response::new(&mut headers);
            if let Ok(Status::Complete(n)) = response.parse(&buf[..]) {
                // FIXME: consume body
                completed = state.pending.pop_front().map(|req| {
                    let status  = response.code.unwrap_or(0);
                    let latency = ts.timespec() - req.ts.timespec();
                    Res{
                        status:  status,
                        url:     req.url,
                        host:    req.host,
                        referer: req.referer,
                        ua:      req.ua,
                        latency: latency,
                    }
                });
                remainder -= n;
            }
        }

        buf.keep(remainder);
        // println!("buffer {:p} currently {:?}", &buf, CString::new(&buf[..]));

        completed
    }
}
