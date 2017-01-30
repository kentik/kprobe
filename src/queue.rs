use std::collections::HashMap;
use std::collections::vec_deque::VecDeque;
use std::time::{SystemTime, Duration};
use flow::*;
use libkflow;

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
    flows:     HashMap<Key, Counter>,
    pending:   HashMap<Addr, VecDeque<PendingQuery>>,
    completed: HashMap<Addr, Vec<CompletedQuery>>,
    flushed:   SystemTime,
}

impl FlowQueue {
    pub fn new() -> FlowQueue {
        FlowQueue {
            flows:     HashMap::new(),
            pending:   HashMap::new(),
            completed: HashMap::new(),
            flushed:   SystemTime::now(),
        }
    }

    pub fn add(&mut self, dir: Direction, mut flow: Flow, bytes: usize) {
        let key = Key(flow.protocol, flow.src, flow.dst);
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
        ctr.bytes   += bytes as u64;

        if let Transport::TCP { flags } = flow.transport {
            ctr.tcp_flags |= flags;
        }

        let pending = &mut self.pending;
        let completed = &mut self.completed;

        flow.payload.take().map(|ps| {
            for p in ps {
                if let Payload::Postgres(Postgres::Query(ref query)) = p {
                    let vec = pending.entry(flow.src).or_insert_with(VecDeque::new);
                    vec.push_back(PendingQuery{
                        query: query.clone(),
                        start: flow.timestamp,
                    });
                }

                if let Payload::Postgres(Postgres::QueryComplete) = p {
                    if let Some(pq) = pending.get_mut(&flow.dst).and_then(|p| p.pop_front()) {
                        if let Ok(time) = flow.timestamp.duration_since(pq.start) {
                            let vec = completed.entry(flow.src).or_insert_with(Vec::new);
                            vec.push(CompletedQuery{
                                query:    pq.query,
                                duration: time,
                            })
                        }
                    }
                }
            }
        });
    }

    pub fn flush(&mut self) {
        if let Ok(time) = self.flushed.elapsed() {
            if time.as_secs() < 10 {
                return;
            }
        }

        for (key, ctr) in &self.flows {
            let src = format!("{}:{}", key.1.addr, key.1.port);
            let dst = format!("{}:{}", key.2.addr, key.2.port);

            println!("{:?} {}->{} PACKETS {} BYTES {}", key.0, src, dst, ctr.packets, ctr.bytes);

            if let Some(queries) = self.completed.remove(&key.1) {
                for completed in queries {
                    let s = completed.duration.as_secs();
                    let ms = completed.duration.subsec_nanos() / 1_000_000;
                    println!("  SQL query: {}", completed.query);
                    println!("  SQL time:  {}.{}s", s, ms);
                }
            }

            libkflow::send(key, ctr).expect("failed to send flow");
        }

        self.flows.clear();
        self.completed.clear();
        self.flushed = SystemTime::now();
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
