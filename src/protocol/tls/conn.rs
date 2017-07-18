use std::ffi::CString;
use time::Duration;
use nom::IResult::*;
use super::parser::*;
use protocol::buf::Buffer;
use flow::Timestamp;

pub struct Connection {
    buffer: Buffer,
    last:   Timestamp,
    state:  State,
}

#[derive(Debug, Default)]
pub struct State {
    pub client_ver:   Option<Version>,
    pub server_ver:   Option<Version>,
    pub host_name:    Option<CString>,
    pub cipher_suite: Option<CipherSuite>,
    pub shaken:       bool,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            buffer: Buffer::new(),
            last:   Timestamp::zero(),
            state:  Default::default(),
        }
    }

    pub fn parse(&mut self, ts: Timestamp, buf: &[u8]) {
        let mut state = &mut self.state;

        self.last = ts;

        if !state.shaken {
            let mut buf = self.buffer.buf(buf);
            let mut remainder = buf.len();

            remainder = match parse_records(&buf) {
                Done(rest, rs) => state.update(rs, rest),
                Incomplete(..) => remainder,
                Error(..)      => 0,
            };

            buf.keep(remainder);
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn is_idle(&self, ts: Timestamp, timeout: Duration) -> bool {
        self.buffer.is_empty() || (ts - self.last) > timeout
    }
}

impl State {
    fn update(&mut self, rs: Vec<Record>, rest: &[u8]) -> usize {
        for r in rs {
            match r {
                Record::Hello(Hello::Client(ver, host))  => {
                    self.client_ver = Some(ver);
                    self.host_name  = host;
                },
                Record::Hello(Hello::Server(ver, suite)) => {
                    self.server_ver   = Some(ver);
                    self.cipher_suite = Some(suite);
                },
                Record::Hello(Hello::Done)               => {
                    self.shaken = true;
                }
                _                                        => (),
            }
        }
        rest.len()
    }
}
