//! The node side of roxy's control-plane protocol: enrolment, lease
//! refresh and flow shipping. Nothing in here knows about the proxy; the
//! `roxy` binary applies what the node fetches.

pub mod client;
pub mod identity;
pub mod node;
pub mod protocol;
pub mod spool;
pub mod state;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
