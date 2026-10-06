//! The node side of roxy's control-plane protocol: enrolment, lease
//! refresh and flow shipping. Nothing in here knows about the proxy; the
//! `roxy` binary applies what the node fetches.

pub mod client;
pub mod identity;
pub mod protocol;
pub mod state;
#[cfg(test)]
mod testkit;
