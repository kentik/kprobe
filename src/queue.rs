use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::collections::vec_deque::VecDeque;
use std::time::{SystemTime, Duration};
use flow::*;

pub struct FlowQueue {
    flows:     HashMap<(Protocol, Addr), Flow>,
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

    pub fn add(&mut self, mut flow: Flow) {
        let payload = flow.payload.take();

        let key = (flow.protocol, flow.src);
        let flow = match self.flows.entry(key) {
            Entry::Occupied(entry) => {
                let existing = entry.into_mut();
                existing.timestamp = flow.timestamp;
                existing.packets  += 1;
                existing.bytes    += flow.bytes;
                existing
            },
            Entry::Vacant(entry) => entry.insert(flow),
        };

        let pending = &mut self.pending;
        let completed = &mut self.completed;

        payload.map(|ps| {
            for p in ps {
                if let Payload::Postgres(Postgres::Query(ref query)) = p {
                    let vec = pending.entry(flow.src).or_insert_with(|| VecDeque::new());
                    vec.push_back(PendingQuery{
                        query: query.clone(),
                        start: flow.timestamp,
                    });
                }

                if let Payload::Postgres(Postgres::QueryComplete) = p {
                    if let Some(pq) = pending.get_mut(&flow.dst).and_then(|p| p.pop_front()) {
                        if let Ok(time) = flow.timestamp.duration_since(pq.start) {
                            let vec = completed.entry(flow.src).or_insert_with(|| Vec::new());
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
            if time.as_secs() < 2 {
                return;
            }
        }

        for (_, flow) in &self.flows {
            let src = format!("{}:{}", flow.src.addr, flow.src.port);
            let dst = format!("{}:{}", flow.dst.addr, flow.dst.port);

            println!("{:?} {}->{} PACKETS {} BYTES {}", flow.protocol, src, dst, flow.packets, flow.bytes);

            if let Some(queries) = self.completed.remove(&flow.src) {
                for completed in queries {
                    let s = completed.duration.as_secs();
                    let ms = completed.duration.subsec_nanos() / 1_000_000;
                    println!("  SQL query: {}", completed.query);
                    println!("  SQL time:  {}.{}s", s, ms);
                }
            }
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
