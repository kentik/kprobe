use time;
use crate::custom;
use super::conn;
use crate::flow::{Flow, Timestamp};

pub struct Decoder {
    code_col_id:      u64,
    length_col_id:    u64,
    latency_col_id:   u64,
    user_name_col_id: u64,
    message:          Option<conn::Message>,
    tracker:          conn::Tracker,
}

impl Decoder {
    pub fn new(cs: &custom::Customs) -> Result<Decoder, ()> {
        Ok(Decoder {
            code_col_id:      cs.get(custom::RADIUS_CODE)?,
            length_col_id:    cs.get(custom::RADIUS_LENGTH)?,
            latency_col_id:   cs.get(custom::APP_LATENCY)?,
            user_name_col_id: cs.get(custom::RADIUS_ATTR_USER_NAME)?,
            message:          None,
            tracker:          conn::Tracker::new(),
        })
    }

    pub fn decode(&mut self, flow: &Flow, cs: &mut custom::Customs) -> bool {
        // println!("Flow: {:#?}", flow.timestamp);
        self.message = conn::parse(flow);
        let msg = match &self.message {
            Some(message) => message,
            _             => return false,
        };

        cs.add_u32(self.code_col_id, msg.code.into());
        cs.add_u32(self.length_col_id, msg.length.into());

        if let Some(user) = &msg.user {
            cs.add_str(self.user_name_col_id, user.as_ref());
        }

        if let Some(latency) = self.tracker.observe(&msg, flow.src, flow.dst, flow.timestamp) {
            cs.add_latency(self.latency_col_id, latency);
        }

        true
    }

    pub fn clear(&mut self, _ts: Timestamp, _timeout: time::Duration) {}
}
