use std::collections::HashMap;
use std::fmt::Write;
use time::Duration;
use nom::IResult::Done;
use super::parser::{self, QQ, Rdata};
use protocol::buf::Buffer;
use flow::Timestamp;

pub struct Connection {
    buffer: Buffer,
    state:  State,
}

struct State {
    pending: HashMap<u16, Timestamp>,
}

#[derive(Debug)]
pub enum Message {
    Query(QQ),
    Reply(QQ, u8, String, Duration),
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            buffer: Buffer::new(),
            state:  State {
                pending: HashMap::new(),
            },
        }
    }

    pub fn parse(&mut self, ts: Timestamp, buf: &[u8]) -> Option<Message> {
        let state = &mut self.state;
        let mut buf = self.buffer.buf(buf);
        let mut completed = None;
        let mut remainder = buf.len();

        if let Done(rest, msg) = parser::parse_message(&buf[..]) {
            completed = state.update(msg, ts);
            remainder = rest.len();
        }

        buf.keep(remainder);

        completed
    }
}

impl State {
    fn update(&mut self, mut msg: parser::Message, ts: Timestamp) -> Option<Message> {
        if msg.header.qr == 0 {
            self.pending.insert(msg.header.id, ts);
            msg.query.pop().map(Message::Query)
        } else {
            let reply_ts = ts.timespec();
            let query_ts = self.pending.remove(&msg.header.id)
                .map(|ts| ts.timespec())
                .unwrap_or(reply_ts);

            msg.query.pop().map(|qq| {
                let mut s = String::new();
                for (i, rr) in msg.answer.iter().enumerate() {
                    if i > 0 {
                        s.push(';');
                    }

                    match rr.rdata {
                        Rdata::A(ref ip)     => write!(&mut s, "{}/A", ip),
                        Rdata::Aaaa(ref ip)  => write!(&mut s, "{}/AAAA", ip),
                        Rdata::Cname(ref cn) => write!(&mut s, "{}/CNAME", cn),
                        Rdata::Ptr(ref ptr)  => write!(&mut s, "{}/PTR", ptr),
                        Rdata::Mx(_, ref mx) => write!(&mut s, "{}/MX", mx),
                        Rdata::Ns(ref ns)    => write!(&mut s, "{}/NS", ns),
                        Rdata::Txt(ref txt)  => write!(&mut s, "{}/TXT", txt.join("")),
                        Rdata::Other(..)     => Ok(()),
                        Rdata::Soa{..}       => Ok(()),
                    }.expect("failed decoding DNS reply");
                }
                Message::Reply(qq, msg.header.rcode, s, reply_ts - query_ts)
            })
        }
    }
}
