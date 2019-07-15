use time;
use crate::custom;
use super::conn;
use crate::flow::{Flow, Timestamp};

use std::default::Default;

#[derive(Default)]
pub struct Decoder {
    code_col_id:      u64,
    latency_col_id:   u64,
    user_name_col_id: u64,
    message:          Option<conn::Message>,
    tracker:          conn::Tracker,
}

impl Decoder {
    pub fn new(cs: &custom::Customs) -> Result<Decoder, ()> {
        Ok(Decoder {
            code_col_id:      cs.get(custom::RADIUS_CODE)?,
            latency_col_id:   cs.get(custom::APP_LATENCY)?,
            user_name_col_id: cs.get(custom::RADIUS_A_USER_NAME)?,
            
            tracker:          conn::Tracker::new(),
            ..Default::default()
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
