use std::collections::HashMap;
use std::collections::VecDeque;
use time::Duration;
use nom::IResult::Done;
use crate::protocol::buf::Buffer;
use crate::flow::Timestamp;
use super::parser::{self, Message};
use self::Message::*;

pub struct Connection {
    buffer_fe: Buffer,
    buffer_be: Buffer,
    state:     State,
}

struct State {
    statements: HashMap<String, String>,
    portals:    HashMap<String, String>,
    executing:  VecDeque<Command>,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            buffer_fe: Buffer::new(),
            buffer_be: Buffer::new(),
            state:  State {
                statements: HashMap::new(),
                portals:    HashMap::new(),
                executing:  VecDeque::new(),
            },
        }
    }

    pub fn frontend_msg(&mut self, ts: Timestamp, buf: &[u8]) -> Option<Vec<CompletedQuery>> {
        let state = &mut self.state;
        let mut buf = self.buffer_fe.buf(buf);
        let mut completed = None;
        let mut remainder = buf.len();

        if let Done(rest, msgs) = parser::parse_frontend(&buf[..]) {
            completed = Some(msgs.iter().flat_map(|m| state.next(ts, m)).collect());
            remainder = rest.len();
        }
        buf.keep(remainder);

        completed
    }

    pub fn backend_msg(&mut self, ts: Timestamp, buf: &[u8]) -> Option<Vec<CompletedQuery>> {
        let state = &mut self.state;
        let mut buf = self.buffer_be.buf(buf);
        let mut completed = None;
        let mut remainder = buf.len();

        if let Done(rest, msgs) = parser::parse_backend(&buf[..]) {
            completed = Some(msgs.iter().flat_map(|m| state.next(ts, m)).collect());
            remainder = rest.len();
        }
        buf.keep(remainder);

        completed
    }
}

impl State {
    fn next(&mut self, ts: Timestamp, msg: &Message) -> Option<CompletedQuery> {
        // println!("postgres msg {:#?}", msg);
        match *msg {
            Query(query)                => self.simple(ts, query),
            Parse{statement, query, ..} => self.parse(statement, query),
            Bind{portal, statement, ..} => self.bind(portal, statement),
            Execute{portal, ..}         => self.execute(ts, portal),
            Close{what, name}           => self.close(what, name),
            RowDescription{..}          => None,
            DataRow{..}                 => None,
            Flush                       => None,
            Sync                        => None,
            ref msg                     => self.done(ts, msg)
        }
    }

    fn simple(&mut self, ts: Timestamp, query: &str) -> Option<CompletedQuery> {
        self.executing.push_back(Command::Query{
            query: query.to_string(),
            start: ts,
        });
        None
    }

    fn parse(&mut self, statement: &str, query: &str) -> Option<CompletedQuery> {
        self.executing.push_back(Command::Parse{
            statement: statement.to_string(),
            query:     query.to_string()
        });
        None
    }

    fn bind(&mut self, portal: &str, statement: &str) -> Option<CompletedQuery> {
        self.executing.push_back(Command::Bind{
            portal:    portal.to_string(),
            statement: statement.to_string(),
        });
        None
    }

    fn execute(&mut self, ts: Timestamp, portal: &str) -> Option<CompletedQuery> {
        self.executing.push_back(Command::Execute{
            portal: portal.to_string(),
            start:  ts,
        });
        None
    }

    fn close(&mut self, what: u8, name: &str) -> Option<CompletedQuery> {
        match what {
            b'S' => self.statements.remove(name),
            b'P' => self.portals.remove(name),
            _    => unreachable!(),
        };
        None
    }

    fn done(&mut self, ts: Timestamp, m: &Message) -> Option<CompletedQuery> {
        self.executing.pop_front().and_then(|p| {
            match p.result(m) {
                Result::QueryComplete{query, start} => {
                    let duration = ts - start;
                    Some(CompletedQuery{
                        query:    query,
                        duration: duration,
                    })
                }
                Result::Parsed{statement, query} => {
                    self.statements.insert(statement, query);
                    None
                },
                Result::Bound{portal, statement} => {
                    self.portals.insert(portal, statement);
                    None
                },
                Result::Executed{portal, start} => {
                    let duration = ts - start;
                    self.portals.get(&portal).and_then(|statement| {
                        self.statements.get(statement).and_then(|query| {
                            Some(CompletedQuery{
                                query:    query.clone(),
                                duration: duration,
                            })
                        })
                    })
                },
                Result::Continue(pending) => {
                    self.executing.push_front(pending);
                    None
                }
                Result::Failed => {
                    None
                }
            }
        })
    }
}

enum Command {
    Query{query: String, start: Timestamp},
    Parse{statement: String, query: String},
    Bind{portal: String, statement: String},
    Execute{portal: String, start: Timestamp},
}

impl Command {
    fn result(self, m: &Message) -> Result {
        use self::Command::*;
        use self::Result::*;

        match (self, m) {
            (Query{query, start}, &ReadyForQuery(..))      => QueryComplete{query, start},
            (query @ Query{..}, &CommandComplete(..))      => Continue(query),
            (Query{..}, &Error(..))                        => Failed,
            (Parse{statement, query}, &ParseComplete)      => Parsed{statement, query},
            (Parse{..}, &Error(..))                        => Failed,
            (Bind{portal, statement}, &BindComplete)       => Bound{portal, statement},
            (Execute{portal, start}, &CommandComplete(..)) => Executed{portal, start},
            (Execute{portal, start}, &EmptyQueryResponse)  => Executed{portal, start},
            (Execute{..}, &Error(..))                      => Failed,
            (this, _)                                      => Continue(this),
        }
    }
}

enum Result {
    QueryComplete{query: String, start: Timestamp},
    Parsed{statement: String, query: String},
    Bound{portal: String, statement: String},
    Executed{portal: String, start: Timestamp},
    Continue(Command),
    Failed,
}

#[derive(Debug)]
pub struct CompletedQuery {
    pub query:    String,
    pub duration: Duration,
}

impl ::std::fmt::Debug for Connection {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        let mut s = fmt.debug_struct("Connection");
        s.field("buffer_fe", &self.buffer_fe.len());
        s.field("buffer_be", &self.buffer_be.len());
        //s.field("state", &self.state);
        s.finish()
    }
}
