//! Host bindings for the `roxy:addon` WIT package (`wit/addon.wit`).
//!
//! Generated code only. The WASI interfaces map onto `wasmtime-wasi`, so a
//! body stream is the same `input-stream` / `output-stream` resource that
//! crate implements; `pending-response` is this crate's own.

wasmtime::component::bindgen!({
    path: "../../wit",
    world: "roxy:addon/layer",
    imports: { default: async | trappable },
    exports: { default: async },
    require_store_data_send: true,
    with: {
        "wasi:io": wasmtime_wasi::p2::bindings::io,
        "wasi:clocks": wasmtime_wasi::p2::bindings::clocks,
        "wasi:random": wasmtime_wasi::p2::bindings::random,
        "wasi:cli": wasmtime_wasi::p2::bindings::cli,
        "roxy:addon/types.pending-response": crate::streams::PendingResponse,
    },
});
