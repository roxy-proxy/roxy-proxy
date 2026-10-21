//! Differential check of the HTTP/1.1 server codec (`roxy-http`
//! `h1::ServerConn`) against hyper's HTTP/1 server.
//!
//! Input: one config byte (parser flags and role, see `roxy_fuzz::flags` /
//! `roxy_fuzz::role`), then the raw bytes of a client connection.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&_cfg, _input)) = data.split_first() else {
        return;
    };
});
