use time;
use crate::custom::*;
// use super::conn::{Connection, Message};
use crate::flow::{Flow, Timestamp};
use super::parser;
use nom::IResult::Done;

pub struct Decoder {
    code_col_id: u64,
    length_col_id: u64,
}

impl Decoder {
    pub fn new(cs: &Customs) -> Result<Decoder, ()> {
        Ok(Decoder {
            code_col_id: cs.get(RADIUS_CODE)?,
            length_col_id: cs.get(RADIUS_LENGTH)?,
            // conn: Connection::new(),
        })
    }

    pub fn decode(&mut self, flow: &Flow, cs: &mut Customs) -> bool {
        let message = match parser::message(flow.payload) {
            Done(_,msg) => Some(msg),
            _           => None,
        };

        message.as_ref().map(|msg| {
            cs.add_u32(self.code_col_id, msg.code.into());
            cs.add_u32(self.length_col_id, msg.length);
            true
        }).unwrap_or(false)
    }

    pub fn clear(&mut self, _ts: Timestamp, _timeout: time::Duration) {}
}
