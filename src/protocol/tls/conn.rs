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

#[derive(Debug)]
pub struct State {
    pub client_ver:   Option<Version>,
    pub server_ver:   Option<Version>,
    pub host_name:    Option<CString>,
    pub cipher_suite: Option<CipherSuite>,
    pub parsing:      bool,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            buffer: Buffer::new(),
            last:   Timestamp::zero(),
            state:  State::new(),
        }
    }

    pub fn parse(&mut self, ts: Timestamp, buf: &[u8]) {
        let mut state = &mut self.state;

        self.last = ts;

        if state.parsing {
            let mut buf = self.buffer.buf(buf);
            let mut remainder = buf.len();

            remainder = match parse_records(&buf) {
                Done(rest, rs) => state.update(rs, rest),
                Incomplete(..) => state.partial(remainder),
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
    fn new() -> Self {
        State{
            client_ver:   None,
            server_ver:   None,
            host_name:    None,
            cipher_suite: None,
            parsing:      true,
        }
    }

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
                    self.parsing = false;
                },
                Record::Unsupported(ver)                 => {
                    self.client_ver = Some(ver);
                    self.server_ver = Some(ver);
                    self.parsing    = false;
                },
                _                                        => (),
            }
        }
        rest.len()
    }

    fn partial(&mut self, len: usize) -> usize {
        if len > 4096 {
            self.parsing = false;
            return 0;
        }
        len
    }
}
