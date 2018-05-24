pub mod id;

#[cfg(feature = "netlink")]
#[path = "netlink.rs"]
mod tracker;

#[cfg(not(feature = "netlink"))]
#[path = "tracker.rs"]
mod tracker;

pub use self::tracker::Tracker;
