//! roxy's proxy engine: listeners, the connection state
//! machine, the exchange core, the upstream connector (DNS, SSRF policy,
//! pool), the WebSocket relay and flow-log emission.
//!
//! # Module map
//!
//! - [`server`]: [`Server`] (`start`, `local_addrs`, `reload`, `shutdown`),
//!   connection caps, the atomically swapped policy snapshot.
//! - [`listener`]: the [`Listener`] trait (the hook for transparent mode, issue #15) and
//!   [`TcpProxyListener`] (explicit and direct); [`ClientConn`].
//! - `conn`: the connection state machines (proxy port, CONNECT, direct
//!   listeners, sniff, TLS termination, tunnels, `roxy.internal`).
//! - `dns_server`: the DNS listener (UDP and TCP) that steers clients to
//!   the direct listeners.
//! - `pipeline`: the core's fixed request and response steps, the
//!   `Verdict` they return (consumed exhaustively), the head decision and
//!   its effects, the per-flow context.
//! - `watch`: the per-exchange watcher: watching rules re-checked as body
//!   bytes stream, at the response head and in the WebSocket relay, and
//!   byte metrics recorded as they stream.
//! - `exchange`: the transport-agnostic exchange core (`process`: request
//!   steps → upstream → response steps → `Outcome`), the h1 adapter,
//!   upstream errors, the WebSocket relay.
//! - `h2conn`: the client-side HTTP/2 front end (ALPN `h2` in a tunnel).
//! - [`upstream`]: resolver, address floor, connector and pooled client.
//! - [`addr`]: the private-range / CIDR address floor.
//! - [`addrlist`]: compiled address lists (`upstream.deny_lists`, `@list`).
//! - [`sources`]: the metric and state store traits.
//! - [`flowlog`]: flow events, sinks and redaction. The file and stdout
//!   sinks write through `roxy-log` (one writer thread, batching,
//!   backpressure, rotation).
//! - [`io`]: stream adapters.
//! - `budget`: the process-wide byte budget for per-exchange buffers.

pub mod addons;
pub mod addr;
pub mod addrlist;
mod body;
mod budget;
mod ca_server;
pub mod capture;
pub mod config;
mod conn;
mod dns_server;
mod exchange;
pub mod flowlog;
mod h2conn;
pub mod io;
pub mod listener;
mod pipeline;
pub mod server;
pub mod sources;
#[cfg(test)]
mod testkit;
pub mod upstream;
mod view;
mod watch;

pub use addrlist::{AddressList, AddressLists, ListError};
pub use ca_server::PEM_CONTENT_TYPE;
pub use capture::{CAPTURE_FILE, CaptureLog, CaptureOptions};
pub use config::{HttpBehaviour, ListenerKind, ListenerSpec, PolicyUpdate, RuntimeConfig};
pub use conn::INTERNAL_HOST;
pub use dns_server::DnsServerSpec;
pub use flowlog::{
    BufferedSink, ClientInfo, DEFAULT_REDACTED_HEADERS, DecisionKind, DstInfo, FileSink, FlowEvent,
    FlowSink, MemorySink, MultiSink, REDACTED, Redactor, RequestInfo, ResponseInfo, Stage,
    StdoutSink, Timing, TlsInfo,
};
pub use listener::{ClientConn, Listener, ListenerInfo, ListenerMode, TcpProxyListener};
pub use server::{Server, ServerHandle, StartError};
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
