//! Host bindings for the `roxy:addon` WIT package (`wit/addon.wit`).
//!
//! Generated code only. The WASI interfaces map onto `wasmtime-wasi` and
//! `wasmtime-wasi-http`, so their resources (requests, bodies, streams) are
//! the same types those crates implement.

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "roxy:addon/tunnel-layer",
    imports: { default: async | trappable },
    exports: { default: async },
    require_store_data_send: true,
    with: {
        "wasi:io": wasmtime_wasi::p2::bindings::io,
        "wasi:clocks": wasmtime_wasi::p2::bindings::clocks,
        "wasi:random": wasmtime_wasi::p2::bindings::random,
        "wasi:cli": wasmtime_wasi::p2::bindings::cli,
        "wasi:http": wasmtime_wasi_http::p2::bindings::http,
    },
});
