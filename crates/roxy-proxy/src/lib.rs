//! roxy's proxy engine: listeners, the connection state
//! machine, addon stages, upstream processing and flow-log emission.
//! The core stage validates the forwarded request, evaluates rules,
//! connects upstream through the address policy, and owns the upstream
//! upload and any WebSocket relay until completion.
//!
//! # Module map
//!
//! - [`server`]: [`Server`] (`start`, `local_addrs`, `reload`, `shutdown`),
//!   connection caps, the atomically swapped policy snapshot.
//! - [`secrets`]: the live secret map and its redactor, swapped
//!   independently of the snapshot.
//! - [`listener`]: the [`Listener`] trait and [`TcpProxyListener`];
//!   [`ClientConn`].
//! - `conn`: the connection state machines (proxy port, CONNECT, sniff,
//!   TLS termination, tunnels, `roxy.internal`).
//! - `pipeline`: the core stage's fixed request and response steps, the
//!   `Verdict` they return (consumed exhaustively), the admission decision and
//!   its effects, the per-flow context.
//! - `in_flight`: the per-exchange in-flight checker: rules re-checked as body
//!   bytes stream, at the response head and in the WebSocket relay, and
//!   byte metrics recorded as they stream.
//! - `exchange`: starts an exchange through the addon chain or directly
//!   through the core stage, returns its HTTP outcome, and writes the final
//!   record after reclamation. Also contains the HTTP/1.1 transport adapter.
//! - `exchange::ws`: the WebSocket relay after a `101`: the byte splice
//!   and the message relay.
//! - `h2conn`: the client-side HTTP/2 transport (ALPN `h2` in a tunnel).
//! - [`upstream`]: resolver, address floor, connector and pooled client.
//! - [`addr`]: the private-range / CIDR address floor.
//! - [`addrlist`]: compiled address lists (`upstream.deny_lists`, `@list`).
//! - [`sources`]: the metric and state store traits.
//! - [`flowlog`]: flow events, sinks and redaction. The file and stdout
//!   sinks write through `roxy-log` (one writer thread, batching,
//!   backpressure, rotation).
//! - [`io`]: stream adapters.
//! - `budget`: the process-wide byte budget for per-exchange buffers.
//! - [`needles`]: the secret matcher and its byte-for-byte mask, shared
//!   by the flow log's redaction and the response masking.
//! - `redact`: masking injected secrets in a response, head and streaming
//!   body.

pub mod addons;
pub mod addr;
pub mod addrlist;
mod body;
mod budget;
mod ca_server;
pub mod capture;
pub mod config;
mod conn;
mod exchange;
pub mod flowlog;
mod forwarded;
mod h2conn;
mod in_flight;
pub mod io;
pub mod listener;
pub mod needles;
mod pipeline;
pub mod quarantine;
mod redact;
pub mod secrets;
pub mod server;
mod sign;
pub mod sources;
#[cfg(test)]
mod testkit;
pub mod upstream;
mod view;

pub use addrlist::{AddressList, AddressLists, ListError};
pub use ca_server::{PEM_CONTENT_TYPE, POLICY_HEADER};
pub use capture::{CAPTURE_FILE, CaptureLog, CaptureOptions};
pub use config::{HttpBehaviour, ListenerSpec, PolicyUpdate, ResponseRedaction, RuntimeConfig};
pub use conn::INTERNAL_HOST;
pub use flowlog::{
    BufferedSink, ClientInfo, DEFAULT_REDACTED_HEADERS, DecisionKind, DstInfo, FileSink, FlowEvent,
    FlowSink, MemorySink, MultiSink, PeerInfo, REDACTED, Redactor, RequestInfo, ResponseInfo,
    Stage, StdoutSink, Timing, TlsInfo,
};
pub use listener::{
    ClientConn, ForwardedFor, Listener, ListenerInfo, ListenerMode, TcpProxyListener,
};
pub use quarantine::{ParseErrorThreshold, QuarantineCause, QuarantineRecord, QuarantineState};
pub use server::{PreparedReload, Server, ServerHandle, StartError};
pub use sources::{
    MetricSource, MetricSourceError, Sample, StateFull, StateSource, UnavailableMetrics,
    UnavailableState,
};
pub use upstream::{ConnectError, DnsSettings, UpstreamSettings};

/// The `roxy-log` writer types behind the file and stdout sinks.
pub mod logging {
    pub use roxy_log::{
        DEFAULT_HIGH_WATER, Destination, LogWriter, RotateOptions, RotatingFile, Stream,
        WriterOptions,
    };
}
