//! Who is to blame when an exchange does not get the response it asked
//! for.
//!
//! Every party records its own failure before anything downstream of it
//! can fail on it: a layer as it fails (before its bodies end), a body
//! where it enters the stack (before its error reaches a reader), the front
//! as it gives the exchange up (before the stack sees the drop). So the
//! first fault recorded is the cause and every later one a consequence,
//! and nothing weighs one against another: the recorder keeps the first
//! and logs it, once, when it is a layer's.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use roxy_http::{Body, BodyError, ParseError, Reason};

use super::{AddonMode, StackError, StackFlow, emit_stack_error};
use crate::pipeline::{FlowMeta, body_failure};

/// Why the exchange is not getting the response it asked for.
#[derive(Debug, Clone)]
pub(crate) enum Fault {
    /// Layer `name` failed. Logged as `layer_error` once: as recorded when
    /// the response head is already out, else with the stack's refusal.
    Layer { name: String, err: StackError },
    /// The client's request body failed on its way in (framing, a cut, a
    /// timeout), or the front gave the exchange up: the exchange closes as
    /// a client's would without a stack.
    Client(ParseError),
    /// The upstream's response body failed before a layer had answered
    /// with a head of its own: the `502` the core would give.
    UpstreamBody,
    /// The buffer budget could not cover a body on its way to a layer (a
    /// decoder's window): fails closed, `buffer_budget_exhausted`.
    Budget,
}

impl Fault {
    /// The flow log's code for the fault: the `reason` of the refusal it
    /// gets before the head, and of the `request` event when it cuts the
    /// body after it.
    pub(crate) fn reason(&self) -> &str {
        match self {
            Fault::Layer { .. } => "layer_error",
            Fault::Client(e) => e.reason.as_str(),
            Fault::UpstreamBody => "upstream_body_failed",
            Fault::Budget => crate::budget::EXHAUSTED,
        }
    }
}

#[derive(Default)]
struct State {
    fault: Option<Fault>,
    /// The response head is on its way to the client: a layer's fault from
    /// now on is logged as it is recorded, since no answer carries it.
    head_out: bool,
    logged: bool,
}

/// The exchange's one record of blame.
pub(crate) struct Attribution {
    meta: Arc<FlowMeta>,
    state: Mutex<State>,
}

impl Attribution {
    pub(crate) fn new(meta: Arc<FlowMeta>) -> Self {
        Self {
            meta,
            state: Mutex::new(State::default()),
        }
    }

    /// Records `fault` unless one stands already.
    pub(crate) fn record(&self, fault: Fault) {
        let mut s = super::lock(&self.state);
        if s.fault.is_some() {
            return;
        }
        if s.head_out
            && let Fault::Layer { name, err } = &fault
        {
            emit_stack_error(&self.meta, name, err, AddonMode::Enforce);
            s.logged = true;
        }
        s.fault = Some(fault);
    }

    /// The response head is going to the client. A layer's fault recorded
    /// before this is logged now; one recorded later is logged as it comes.
    pub(crate) fn head_out(&self) {
        let mut s = super::lock(&self.state);
        s.head_out = true;
        if !s.logged
            && let Some(Fault::Layer { name, err }) = &s.fault
        {
            emit_stack_error(&self.meta, name, err, AddonMode::Enforce);
            s.logged = true;
        }
    }

    /// Logs the standing layer fault with the stack's refusal, before the
    /// head.
    pub(crate) fn log(&self) {
        let mut s = super::lock(&self.state);
        if !s.logged
            && let Some(Fault::Layer { name, err }) = &s.fault
        {
            emit_stack_error(&self.meta, name, err, AddonMode::Enforce);
            s.logged = true;
        }
    }

    pub(crate) fn fault(&self) -> Option<Fault> {
        super::lock(&self.state).fault.clone()
    }

    pub(crate) fn is_faulted(&self) -> bool {
        super::lock(&self.state).fault.is_some()
    }
}

/// Whose body a stream is where it enters the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// The client's request body.
    Client,
    /// The upstream's response body.
    Upstream,
}

impl Side {
    fn fault(self, e: &BodyError) -> Fault {
        match (self, e) {
            (_, BodyError::BudgetExhausted) => Fault::Budget,
            (Side::Client, e) => Fault::Client(body_failure(e)),
            (Side::Upstream, _) => Fault::UpstreamBody,
        }
    }
}

/// A body whose failure is recorded before its reader sees it.
struct Attributed {
    inner: Body,
    st: Arc<StackFlow>,
    side: Side,
}

impl HttpBody for Attributed {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        let frame = ready!(Pin::new(&mut this.inner).poll_frame(cx));
        if let Some(Err(e)) = &frame {
            this.st.attribution.record(this.side.fault(e));
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// `body` as it enters the stack from `side`: its failure is `side`'s,
/// recorded before any layer reads it.
pub(crate) fn attributed(st: &Arc<StackFlow>, side: Side, body: Body) -> Body {
    let known = body.known_length();
    Body::wrap_native(
        Attributed {
            inner: body,
            st: st.clone(),
            side,
        },
        u64::MAX,
        known,
    )
}

/// The stack's answer as the front drives it. Dropped before it resolved
/// (the front gave the exchange up: the client's body failed, or the
/// client went away), it records that first, so what the layers make of
/// their bodies and `next` ending is a consequence.
pub(crate) struct Driven<F> {
    st: Arc<StackFlow>,
    fut: Pin<Box<F>>,
    done: bool,
}

impl<F: Future> Driven<F> {
    pub(crate) fn new(st: Arc<StackFlow>, fut: F) -> Self {
        Self {
            st,
            fut: Box::pin(fut),
            done: false,
        }
    }
}

impl<F: Future> Future for Driven<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let out = ready!(self.fut.as_mut().poll(cx));
        self.done = true;
        Poll::Ready(out)
    }
}

impl<F> Drop for Driven<F> {
    fn drop(&mut self) {
        if !self.done {
            self.st.attribution.record(Fault::Client(ParseError::new(
                Reason::UnexpectedEof,
                "the exchange ended before the stack answered",
            )));
        }
    }
}
