use time;
use crate::custom;
use super::conn;
use crate::flow::{Flow, Timestamp};

use std::default::Default;

#[derive(Default)]
pub struct Decoder {
    code_col_id:            u64,
    latency_col_id:         u64,
    user_name_col_id:       u64,
    service_type_col_id:    u64,
    framed_ip_col_id:       u64,
    framed_mask_col_id:     u64,
    framed_proto_col_id:    u64,
    acct_session_id_col_id: u64,
    acct_status_col_id:     u64,
    message:                Option<conn::Message>,
    tracker:                conn::Tracker,
}

impl Decoder {
    pub fn new(cs: &custom::Customs) -> Result<Decoder, ()> {
        Ok(Decoder {
            code_col_id:            cs.get(custom::RADIUS_CODE)?,
            latency_col_id:         cs.get(custom::APP_LATENCY)?,
            user_name_col_id:       cs.get(custom::RADIUS_A_USER_NAME)?,
            acct_status_col_id:     cs.get(custom::RADIUS_A_ACCT_STATUS)?,
            service_type_col_id:    cs.get(custom::RADIUS_A_SERVICE_TYPE)?,
            framed_ip_col_id:       cs.get(custom::RADIUS_A_FRAMED_IP_ADDR)?,
            framed_mask_col_id:     cs.get(custom::RADIUS_A_FRAMED_IP_MASK)?,
            framed_proto_col_id:    cs.get(custom::RADIUS_A_FRAMED_PROTO)?,
            acct_session_id_col_id: cs.get(custom::RADIUS_A_ACCT_SESSION_ID)?,

            tracker:          conn::Tracker::new(),
            ..Default::default()
        })
    }

    pub fn decode(&mut self, flow: &Flow, cs: &mut custom::Customs) -> bool {
        self.message = conn::parse(flow);
        let msg = match &self.message {
            Some(message) => message,
            _             => return false,
        };

        cs.add_u32(self.code_col_id, msg.code.into());

        if let Some(latency) = self.tracker.observe(&msg, flow.src, flow.dst, flow.timestamp) {
            cs.add_latency(self.latency_col_id, latency);
        }

        if let Some(user)            = &msg.user            { cs.add_str(self.user_name_col_id, user); }
        if let Some(acct_status)     = msg.acct_status      { cs.add_u32(self.acct_status_col_id, acct_status); }
        if let Some(service_type)    = msg.service_type     { cs.add_u32(self.service_type_col_id, u32::from(service_type)); }
        if let Some(framed_ip)       = msg.framed_ip        { cs.add_addr(self.framed_ip_col_id, framed_ip); }
        if let Some(framed_mask)     = msg.framed_mask      { cs.add_u32(self.framed_mask_col_id, framed_mask); }
        if let Some(framed_proto)    = msg.framed_proto     { cs.add_u32(self.framed_proto_col_id, framed_proto); }
        if let Some(acct_session_id) = &msg.acct_session_id { cs.add_str(self.acct_session_id_col_id, acct_session_id); }
        if let Some(acct_status)     = msg.acct_status      { cs.add_u32(self.acct_status_col_id, acct_status); }

        true
    }

    pub fn clear(&mut self, _ts: Timestamp, _timeout: time::Duration) {}
}
