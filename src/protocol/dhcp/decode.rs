use time::Duration;
use flow::{Flow, Timestamp};
use custom::*;
use super::conn::{Connection, Message};

pub struct Decoder {
    op:      u64,
    msg:     u64,
    ciaddr:  u64,
    yiaddr:  u64,
    siaddr:  u64,
    chaddr:  u64,
    host:    u64,
    domain:  u64,
    lease:   u64,
    latency: u64,
    message: Option<Message>,
    conn:    Connection,
}

impl Decoder {
    pub fn new(cs: &Customs) -> Result<Decoder, ()> {
        Ok(Decoder{
            op:      cs.get(DHCP_OP)?,
            msg:     cs.get(DHCP_MSG_TYPE)?,
            ciaddr:  cs.get(DHCP_CI_ADDR)?,
            yiaddr:  cs.get(DHCP_YI_ADDR)?,
            siaddr:  cs.get(DHCP_SI_ADDR)?,
            chaddr:  cs.get(DHCP_CH_ADDR)?,
            host:    cs.get(DHCP_HOSTNAME)?,
            domain:  cs.get(DHCP_DOMAIN)?,
            lease:   cs.get(DHCP_LEASE)?,
            latency: cs.get(APP_LATENCY)?,
            message: None,
            conn:    Connection::new(),
        })
    }

    pub fn decode(&mut self, flow: &Flow, cs: &mut Customs) -> bool {
        self.message = self.conn.parse(flow.timestamp, flow.payload);
        self.message.as_ref().map(|msg| {
            cs.add_u32(self.op,     msg.op as u32);
            cs.add_u32(self.msg,    msg.msg as u32);
            cs.add_u32(self.ciaddr, msg.ciaddr.into());
            cs.add_u32(self.yiaddr, msg.yiaddr.into());
            cs.add_u32(self.siaddr, msg.siaddr.into());
            cs.add_str(self.chaddr, msg.chaddr.as_ref());
            msg.host.as_ref().map(|s| cs.add_str(self.host, s));
            msg.domain.as_ref().map(|s| cs.add_str(self.domain, s));
            msg.lease.map(|d| cs.add_u32(self.lease, d.num_seconds() as u32));
            msg.latency.map(|d| cs.add_latency(self.latency, d));
            true
        }).unwrap_or(false)
    }

    pub fn clear(&mut self, _ts: Timestamp, _timeout: Duration) {
        return
    }
}
