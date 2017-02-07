use std::collections::HashMap;
use std::collections::VecDeque;

use nom::IResult::Done;
use super::buf::Buffer;
use super::parser::{self, Message};
use self::Message::*;

pub struct Connection {
    buffer_fe: Buffer,
    buffer_be: Buffer,
    state:     State,
}

#[derive(Debug)]
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

    pub fn frontend_msg(&mut self, buf: &[u8]) -> Option<Vec<String>> {
        let state = &mut self.state;
        let mut buf = self.buffer_fe.buf(buf);
        let mut completed = None;
        let mut remainder = buf.len();

        if let Done(rest, msgs) = parser::parse_frontend(&buf[..]) {
            completed = Some(msgs.iter().flat_map(|m| state.next(m)).collect());
            remainder = rest.len();
        }
        buf.keep(remainder);

        completed
    }

    pub fn backend_msg(&mut self, buf: &[u8]) -> Option<Vec<String>> {
        let state = &mut self.state;
        let mut buf = self.buffer_be.buf(buf);
        let mut completed = None;
        let mut remainder = buf.len();

        if let Done(rest, msgs) = parser::parse_backend(&buf[..]) {
            completed = Some(msgs.iter().flat_map(|m| state.next(m)).collect());
            remainder = rest.len();
        }
        buf.keep(remainder);

        completed
    }
}

impl State {
    fn next(&mut self, msg: &Message) -> Option<String> {
        println!("postgres msg {:#?}", msg);
        let res = match *msg {
            Query(query)                => self.simple(query),
            Parse{statement, query, ..} => self.parse(statement, query),
            Bind{portal, statement, ..} => self.bind(portal, statement),
            Execute{portal, ..}         => self.execute(portal),
            Close{what, name}           => self.close(what, name),
            RowDescription{..}          => None,
            DataRow{..}                 => None,
            Flush                       => None,
            Sync                        => None,
            ref msg                     => self.done(msg)
        };
        res
    }

    fn simple(&mut self, query: &str) -> Option<String> {
        self.executing.push_back(Command::Query{
            query: query.to_string()
        });
        None
    }

    fn parse(&mut self, statement: &str, query: &str) -> Option<String> {
        self.executing.push_back(Command::Parse{
            statement: statement.to_string(),
            query:     query.to_string()
        });
        None
    }

    fn bind(&mut self, portal: &str, statement: &str) -> Option<String> {
        self.executing.push_back(Command::Bind{
            portal:    portal.to_string(),
            statement: statement.to_string(),
        });
        None
    }

    fn execute(&mut self, portal: &str) -> Option<String> {
        self.executing.push_back(Command::Execute{
            portal:    portal.to_string(),
        });
        None
    }

    fn close(&mut self, what: u8, name: &str) -> Option<String> {
        match what {
            b'S' => self.statements.remove(name),
            b'P' => self.portals.remove(name),
            _    => unreachable!(),
        }
    }

    fn done(&mut self, m: &Message) -> Option<String> {
        self.executing.pop_front().and_then(|p| {
            match p.result(m) {
                Result::QueryComplete{query} => {
                    Some(query)
                }
                Result::Parsed{statement, query} => {
                    self.statements.insert(statement, query);
                    None
                },
                Result::Bound{portal, statement} => {
                    self.portals.insert(portal, statement);
                    None
                },
                Result::Executed{portal} => {
                    self.portals.get(&portal).and_then(|statement| {
                        self.statements.get(statement).and_then(|query| {
                            Some(query.clone())
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

#[derive(Debug)]
enum Command {
    Query{query: String},
    Parse{statement: String, query: String},
    Bind{portal: String, statement: String},
    Execute{portal: String},
}

impl Command {
    fn result(self, m: &Message) -> Result {
        use self::Command::*;
        use self::Result::*;

        match (self, m) {
            (Query{query}, &ReadyForQuery(..))        => QueryComplete{query},
            (query @ Query{..}, &CommandComplete(..)) => Continue(query),
            (Query{..}, &Error(..))                   => Failed,
            (Parse{statement, query}, &ParseComplete) => Parsed{statement, query},
            (Parse{..}, &Error(..))                   => Failed,
            (Bind{portal, statement}, &BindComplete)  => Bound{portal, statement},
            (Execute{portal}, &CommandComplete(..))   => Executed{portal},
            (Execute{portal}, &EmptyQueryResponse)    => Executed{portal},
            (Execute{..}, &Error(..))                 => Failed,
            (this, _)                                 => Continue(this),
        }
    }
}

#[derive(Debug)]
enum Result {
    QueryComplete{query: String},
    Parsed{statement: String, query: String},
    Bound{portal: String, statement: String},
    Executed{portal: String},
    Continue(Command),
    Failed,
}

impl ::std::fmt::Debug for Connection {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        let mut s = fmt.debug_struct("Connection");
        s.field("buffer_fe", &self.buffer_fe.len());
        s.field("buffer_be", &self.buffer_be.len());
        s.field("state", &self.state);
        s.finish()
    }
}
