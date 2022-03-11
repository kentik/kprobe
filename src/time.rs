use std::fmt;
use std::ops::{Add, Sub};
use libc::timeval;
use time::Duration;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp {
    pub sec:  u64,
    pub nsec: u64,
}

impl Timestamp {
    pub fn now() -> Self {
        let ts   = time::get_time();
        let sec  = ts.sec  as u64;
        let nsec = ts.nsec as u64;
        Self { sec, nsec }
    }

    pub fn zero() -> Self {
        Self::default()
    }
}

impl Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, d: Duration) -> Self::Output {
        let sec  = d.num_seconds() as u64;
        let nsec = d.num_nanoseconds().unwrap_or(0) as u64;
        Self {
            sec:  self.sec.saturating_add(sec),
            nsec: self.nsec.saturating_add(nsec),
        }
    }
}

impl Sub for Timestamp {
    type Output = Duration;

    fn sub(self, ts: Timestamp) -> Self::Output {
        let sec  = self.sec  as i64 - ts.sec  as i64;
        let nsec = self.nsec as i64 - ts.nsec as i64;
        Duration::seconds(sec) + Duration::nanoseconds(nsec)
    }
}

impl From<timeval> for Timestamp {
    fn from(tv: timeval) -> Self {
        Self {
            sec:  tv.tv_sec  as u64,
            nsec: tv.tv_usec as u64 * 1000,
        }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tm = time::at(time::Timespec{
            sec:  self.sec  as i64,
            nsec: self.nsec as i32,
        });

        match time::strftime("%F %T", &tm) {
            Ok(str) => write!(f, "{}", str),
            Err(..) => Err(fmt::Error)
        }
    }
}
