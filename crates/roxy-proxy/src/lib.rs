//! roxy's proxy engine (`DESIGN.md` §3): listeners, the connection state
//! machine, the flow pipeline, the upstream connector (DNS, SSRF policy,
//! pool), the WebSocket relay and flow-log emission.
//!
//! # Module map
//!
//! - [`server`]: [`Server`] (`start`, `local_addrs`, `reload`, `shutdown`),
//!   connection caps, the atomically swapped policy snapshot.
//! - [`listener`]: the [`Listener`] trait (§4.2 hook) and
//!   [`ExplicitListener`]; [`ClientConn`].
//! - `conn`: the explicit-mode state machine (proxy port, CONNECT, sniff,
//!   TLS termination, tunnels, `roxy.internal`, proxy auth).
//! - `pipeline`: request/response stages, the `Verdict` the driver consumes
//!   exhaustively, the head decision and its effects.
//! - `watch`: the per-exchange watcher: watching rules re-checked as body
//!   bytes stream, at the response head and in the WebSocket relay, and
//!   byte metrics recorded as they stream.
//! - `exchange`: the transport-agnostic exchange core (`process`: request
//!   stages → upstream → response stages → `Outcome`), the h1 adapter,
//!   upstream errors, the WebSocket relay.
//! - `h2conn`: the client-side HTTP/2 front end (ALPN `h2` in a tunnel).
//! - [`upstream`]: resolver, address floor, connector and pooled client.
//! - [`addr`]: the private-range / CIDR address floor.
//! - [`addrlist`]: compiled address lists (`upstream.deny_lists`, `@list`).
//! - [`auth`]: `Proxy-Authorization: Basic` against bcrypt users files.
//! - [`sources`]: the metric and state store traits.
//! - [`flowlog`]: flow events, sinks and redaction.
//! - [`logwriter`]: the buffered single-writer destination with
//!   backpressure behind the file and stdout sinks.
//! - [`io`]: stream adapters.
//!
//! # Requested `roxy-http` changes (worked around here)
//!
//! `ServerConn::respond` cannot force `connection: close` on a response the
//! client did not ask to close, and `proxy-authenticate` is a reserved
//! header, so a `407` cannot carry its challenge. [`io::ConnIo`] works
//! around both by adding header lines after the status line and closing the
//! stream itself after the codec is dropped.

pub mod addr;
pub mod addrlist;
pub mod auth;
mod body;
mod ca_server;
pub mod config;
mod conn;
mod exchange;
pub mod flowlog;
mod h2conn;
pub mod io;
pub mod listener;
pub mod logwriter;
mod pipeline;
pub mod server;
pub mod sources;
pub mod upstream;
mod view;
mod watch;

pub use addrlist::{AddressList, AddressLists, ListError};
pub use auth::UserDb;
pub use ca_server::PEM_CONTENT_TYPE;
pub use config::{ListenerSpec, PolicyUpdate, RuntimeConfig};
pub use conn::INTERNAL_HOST;
pub use flowlog::{
    BufferedSink, ClientInfo, DEFAULT_REDACTED_HEADERS, DecisionKind, DstInfo, FileSink, FlowEvent,
    FlowSink, MemorySink, MultiSink, REDACTED, Redactor, RequestInfo, ResponseInfo, Stage,
    StdoutSink, Timing, TlsInfo, WriterSink,
};
pub use listener::{ClientConn, ExplicitListener, Listener, ListenerInfo, ListenerMode};
pub use server::{Server, ServerHandle, StartError};
pub use sources::{
    MetricSource, MetricSourceError, Sample, StateFull, StateSource, UnavailableMetrics,
    UnavailableState,
};
pub use upstream::{ConnectError, DnsSettings, UpstreamSettings};
