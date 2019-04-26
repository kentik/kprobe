use std::mem::swap;
use std::net::Ipv4Addr;
use log::warn;
use nom::IResult::Done;
use pcap::{Capture, Active};
use pcap::Error::*;
use pnet::packet::{Packet as PacketExt};
use pnet::packet::ethernet::EthernetPacket;
use time::Duration;
use kentik_api::tag::{self, *};
use crate::args::Error;
use crate::packet::{self, Transport::UDP};
use crate::protocol::radius::parser;
use crate::reasm::Reassembler;
use crate::flow::Timestamp;
use parser::{Attr::*, AcctStatusType::*};
use parser::Code::AccountingRequest;

pub struct Radius {
    asm:     Reassembler,
    client:  Client,
    upserts: Vec<Upsert>,
    deletes: Vec<Delete>,
    last:    Timestamp,
}

#[derive(Eq, PartialEq, Debug)]
pub enum Request {
    Start(String, Ipv4Addr),
    Stop(String),
}

pub fn run(mut cap: Capture<Active>, client: Client) -> Result<(), Error<'static>> {
    let mut radius = Radius::new(client);

    cap.filter("udp dst portrange 1812-1813")?;

    loop {
        match cap.next() {
            Ok(packet)          => radius.record(packet),
            Err(TimeoutExpired) => radius.flush(Timestamp::now()),
            Err(NoMorePackets)  => return Ok(()),
            Err(e)              => return Err(e.into()),
        }
    }
}

impl Radius {
    pub fn new(client: Client) -> Self {
        Self {
            asm:     Reassembler::new(),
            client:  client,
            upserts: Vec::new(),
            deletes: Vec::new(),
            last:    Timestamp::zero(),
        }
    }

    pub fn record<'a>(&mut self, packet: pcap::Packet<'a>) {
        let eth = match EthernetPacket::new(packet.data) {
            Some(pkt) => pkt,
            None      => return,
        };

        if let (_vlan, Some(pkt)) = packet::decode(&eth) {
            let ts = Timestamp(packet.header.ts);

            if let Some(out) = self.asm.reassemble(ts, &pkt) {
                if let Some(transport) = pkt.transport(&out.data) {
                    let payload = match transport {
                        UDP(ref udp) => udp.payload(),
                        _            => return,
                    };

                    self.parse(payload).map(|r| match r {
                        Request::Start(user, addr) => self.upsert(user, addr),
                        Request::Stop(user)        => self.delete(user),
                    });
                }
            }

            self.flush(ts);
        }
    }

    pub fn parse(&mut self, payload: &[u8]) -> Option<Request> {
        let msg = match parser::message(payload) {
            Done(_, msg) => msg,
            _            => return None,
        };

        if msg.code != AccountingRequest {
            return None;
        }

        let mut kind = None;
        let mut user = None;
        let mut addr = None;

        for attr in msg.attrs {
            match attr {
                AcctStatusType(t) => kind = Some(t),
                UserName(s)       => user = Some(s.to_owned()),
                FramedIPAddr(ip)  => addr = Some(ip),
                _                 => (),
            }
        }

        match (kind, user, addr) {
            (Some(Start), Some(user), Some(addr)) => Some(Request::Start(user, addr)),
            (Some(Stop),  Some(user), _         ) => Some(Request::Stop(user)),
            _                                     => None,
        }
    }

    fn upsert(&mut self, user: String, addr: Ipv4Addr) {
        self.upserts.push(Upsert::Small(Small {
            value:    user,
            criteria: (Rule {
                addr: Some((addr.to_string(),)),
                ..Default::default()
            },)
        }));
    }

    fn delete(&mut self, user: String) {
        self.deletes.push(Delete {
            value: user,
        });
    }

    fn flush(&mut self, ts: Timestamp) {
        if (ts - self.last) >= Duration::seconds(1) {
            let mut upserts = Vec::with_capacity(self.upserts.len());
            let mut deletes = Vec::with_capacity(self.deletes.len());

            swap(&mut self.upserts, &mut upserts);
            swap(&mut self.deletes, &mut deletes);

            let req = tag::Request {
                replace_all: false,
                complete:    true,
                ttl_minutes: 0,
                upserts:     upserts,
                deletes:     deletes,
            };

            let timeout = Duration::milliseconds(10).to_std().unwrap();
            match self.client.send("kt_user", req, timeout) {
                Ok(..) => (),
                Err(e) => warn!("tag queue full: {:?}", e),
            };

            self.asm.flush(ts);
            self.last = ts;
        }
    }
}
