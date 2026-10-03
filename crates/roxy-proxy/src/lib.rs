//! roxy's proxy engine (`DESIGN.md` §3): listeners, the connection state
//! machine, the flow pipeline, the upstream connector (DNS, SSRF policy,
//! pool), the WebSocket relay and flow-log emission.
//!
//! M0 ships only the flow log ([`flowlog`]); the pipeline arrives in M1.

pub mod flowlog;

pub use flowlog::{
    ClientInfo, DEFAULT_REDACTED_HEADERS, DecisionKind, DstInfo, FileSink, FlowEvent, FlowSink,
    MemorySink, MultiSink, REDACTED, Redactor, RequestInfo, ResponseInfo, StdoutSink, Timing,
    TlsInfo, WriterSink,
};
