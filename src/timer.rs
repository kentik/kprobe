use rand;
use rand::distributions::{Range, Sample};
use time::Duration;
use crate::flow::Timestamp;

pub struct Timer {
    delay: Duration,
    next:  Timestamp,
}

impl Timer {
    pub fn new(delay: Duration) -> Self {
        let next = Timestamp::zero();
        Timer{
            delay: delay,
            next:  next,
        }
    }

    pub fn ready(&mut self, ts: Timestamp) -> bool {
        if self.next <= ts {
            let delay = self.delay;
            self.next = ts + delay;
            true
        } else {
            false
        }
    }
}

pub struct Timeout {
    delay: Duration,
    skew:  Range<i64>,
}

impl Timeout {
    pub fn new(delay: Duration) -> Self {
        let skew = Range::new(0, delay.num_seconds() + 1);
        Timeout{
            delay: delay,
            skew:  skew,
        }
    }

    pub fn first(&mut self, ts: Timestamp) -> Timestamp {
        let mut rng = rand::thread_rng();
        let skew = self.skew.sample(&mut rng);
        ts + Duration::seconds(skew)
    }

    pub fn next(&self, ts: Timestamp) -> Timestamp {
        ts + self.delay
    }
}
