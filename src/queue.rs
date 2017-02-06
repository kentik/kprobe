use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use flow::*;
use libkflow;
use protocol::postgres;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Key(pub Protocol, pub Addr, pub Addr);

#[derive(Debug)]
pub struct Counter {
    pub ethernet:  Ethernet,
    pub direction: Direction,
    pub tos:       u8,
    pub tcp_flags: u16,
    pub packets:   u64,
    pub bytes:     u64,
}

#[derive(Debug)]
pub enum Direction {
    In, Out, Unknown
}

pub struct FlowQueue {
    flows:    HashMap<Key, Counter>,
    postgres: HashMap<Addr, postgres::Connection>,
    flushed:  SystemTime,
}

impl FlowQueue {
    pub fn new() -> FlowQueue {
        FlowQueue {
            flows:     HashMap::new(),
            postgres:  HashMap::new(),
            flushed:   SystemTime::now(),
        }
    }

    pub fn add(&mut self, dir: Direction, flow: Flow) {
        let key = Key(flow.protocol, flow.src, flow.dst);
        {
        let ctr = self.flows.entry(key).or_insert_with(|| {
            Counter {
                ethernet:  flow.ethernet,
                direction: dir,
                tos:       0,
                tcp_flags: 0,
                packets:   0,
                bytes:     0,
            }
        });

        ctr.tos     |= flow.tos;
        ctr.packets += 1;
        ctr.bytes   += flow.payload.len() as u64;

        if let Transport::TCP { flags } = flow.transport {
            ctr.tcp_flags |= flags;
        }
        }

        match (flow.src.port, flow.dst.port) {
            (_, 5432) => self.postgres_fe(flow.src, flow.payload),
            (5432, _) => self.postgres_be(flow.dst, flow.payload),
            (_, 5433) => self.postgres_fe(flow.src, flow.payload),
            (5433, _) => self.postgres_be(flow.dst, flow.payload),
            _         => (),
        };
    }

    pub fn flush(&mut self) {
        if let Ok(time) = self.flushed.elapsed() {
            if time.as_secs() < 15 {
                return;
            }
        }

        for (key, ctr) in &self.flows {
            // let src = format!("{}:{}", key.1.addr, key.1.port);
            // let dst = format!("{}:{}", key.2.addr, key.2.port);

            // println!("{:?} {}->{} PACKETS {} BYTES {}", key.0, src, dst, ctr.packets, ctr.bytes);

            // if let Some(queries) = self.completed.remove(&key.1) {
            //     for completed in queries {
            //         let s = completed.duration.as_secs();
            //         let ms = completed.duration.subsec_nanos() / 1_000_000;
            //         println!("  SQL query: {}", completed.query);
            //         println!("  SQL time:  {}.{}s", s, ms);
            //     }
            // }

            libkflow::send(key, ctr).expect("failed to send flow");
        }

        self.flows.clear();
        self.flushed = SystemTime::now();
    }

    fn postgres_fe(&mut self, addr: Addr, p: &[u8]) {
        let conn = self.postgres.entry(addr).or_insert_with(postgres::Connection::new);
        conn.frontend_msg(p);
        println!("connection {:?}: {:#?}", addr, conn);
    }

    fn postgres_be(&mut self, addr: Addr, p: &[u8]) {
        let conn = self.postgres.entry(addr).or_insert_with(postgres::Connection::new);
        conn.backend_msg(p);
        println!("connection {:?}: {:#?}", addr, conn);
    }
}


#[derive(Debug)]
struct PendingQuery {
    query: String,
    start: SystemTime,
}

#[derive(Debug)]
struct CompletedQuery {
    query:    String,
    duration: Duration,
}
