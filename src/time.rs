use std::ffi::CStr;
use std::fmt;
use std::mem::{MaybeUninit, zeroed};
use std::ops::{Add, Sub};
use libc::{self, CLOCK_REALTIME, timespec, timeval, time_t};
use time::Duration;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp {
    pub sec:  u64,
    pub nsec: u64,
}

impl Timestamp {
    pub fn now() -> Self {
        let ts   = gettime();
        let sec  = ts.tv_sec  as u64;
        let nsec = ts.tv_nsec as u64;
        Self { sec, nsec }
    }

    pub fn zero() -> Self {
        Self::default()
    }
}

impl Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, d: Duration) -> Self::Output {
        let sec  = d.whole_seconds() as u64;
        let nsec = d.subsec_nanoseconds() as u64;
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
        write!(f, "{}", format("%F %T", self.sec as time_t))
    }
}

fn gettime() -> timespec {
    unsafe {
        let mut ts = MaybeUninit::uninit();
        match libc::clock_gettime(CLOCK_REALTIME, ts.as_mut_ptr()) {
            0 => ts,
            _ => MaybeUninit::zeroed()
        }.assume_init()
    }
}

fn format(fmt: &str, time: time_t) -> String {
    unsafe {
        let tm = match libc::localtime(&time) {
            tm if !tm.is_null() => *tm,
            _                   => zeroed(),
        };

        let mut str = [0i8; 32];
        let ptr = str.as_mut_ptr();
        let len = str.len() - 1;
        let fmt = fmt.as_ptr() as *const _;

        match libc::strftime(ptr, len, fmt, &tm) {
            n if n > 0 => CStr::from_ptr(ptr),
            _          => CStr::from_bytes_with_nul_unchecked(&[0]),
        }.to_string_lossy().to_string()
    }
}
