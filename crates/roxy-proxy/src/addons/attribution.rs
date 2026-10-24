//! Who is to blame when an exchange does not get the response it asked
//! for.
//!
//! Every party records its own failure before anything downstream of it
//! can fail on it: a layer as it fails (before its bodies end), a body
//! where it enters the stack (before its error reaches a reader), the transport handler
//! as it gives the exchange up (before the stack sees the drop). So the
//! first fault recorded is the cause and every later one a consequence,
//! and nothing weighs one against another: the log keeps the first and
//! logs it, once, when it is a layer's.
//!
//! The same goes for a cut: a lane an enforcing layer cuts is the layer's
//! abort only when no fault and no client loss came before it, since a
//! cut passing through a layer is how an earlier failure reaches the next
//! stage.

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
    /// timeout), or the transport handler gave the exchange up: the exchange closes as
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

/// What happened to the exchange that its record is made from.
#[derive(Debug, Clone)]
enum Event {
    Fault(Fault),
    /// An enforcing layer cut a lane it produces, with nothing earlier to
    /// explain it.
    Aborted,
    /// The client edge saw the client go.
    ClientGone,
    /// The upstream work was cancelled because nothing waited for it.
    UpstreamAbandoned,
}

/// The stack's part of the flow's record, derived from the log once the
/// exchange is over.
#[derive(Debug, Clone, Default)]
pub(crate) struct Cause {
    /// The first fault recorded.
    pub(crate) fault: Option<Fault>,
    /// A layer aborted a lane of its own accord.
    pub(crate) aborted: bool,
    pub(crate) client_gone: bool,
    pub(crate) upstream_abandoned: bool,
}

/// The flow log's code for a layer's abort, and for upstream work it
/// stopped waiting for.
pub(crate) const LAYER_ABORTED: &str = "layer_aborted";

#[derive(Default)]
struct State {
    /// In the order it happened.
    events: Vec<Event>,
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
        if s.fault().is_some() {
            return;
        }
        if s.head_out
            && let Fault::Layer { name, err } = &fault
        {
            emit_stack_error(&self.meta, name, err, AddonMode::Enforce);
            s.logged = true;
        }
        s.events.push(Event::Fault(fault));
    }

    /// An enforcing layer cut a lane it produces. Logged only when nothing
    /// before it explains the cut.
    pub(crate) fn aborted(&self) {
        let mut s = super::lock(&self.state);
        let explained = s
            .events
            .iter()
            .any(|e| matches!(e, Event::Fault(_) | Event::ClientGone | Event::Aborted));
        if !explained {
            s.events.push(Event::Aborted);
        }
    }

    pub(crate) fn client_gone(&self) {
        super::lock(&self.state).events.push(Event::ClientGone);
    }

    pub(crate) fn upstream_abandoned(&self) {
        super::lock(&self.state)
            .events
            .push(Event::UpstreamAbandoned);
    }

    /// The client edge saw the client go.
    pub(crate) fn is_client_gone(&self) -> bool {
        super::lock(&self.state)
            .events
            .iter()
            .any(|e| matches!(e, Event::ClientGone))
    }

    /// What the record is made from.
    pub(crate) fn cause(&self) -> Cause {
        let s = super::lock(&self.state);
        let mut cause = Cause {
            fault: s.fault().cloned(),
            ..Cause::default()
        };
        for e in &s.events {
            match e {
                Event::Fault(_) => {}
                Event::Aborted => cause.aborted = true,
                Event::ClientGone => cause.client_gone = true,
                Event::UpstreamAbandoned => cause.upstream_abandoned = true,
            }
        }
        cause
    }

    /// The response head is going to the client. A layer's fault recorded
    /// before this is logged now; one recorded later is logged as it comes.
    pub(crate) fn head_out(&self) {
        let mut s = super::lock(&self.state);
        s.head_out = true;
        if !s.logged
            && let Some(Fault::Layer { name, err }) = s.fault().cloned()
        {
            emit_stack_error(&self.meta, &name, &err, AddonMode::Enforce);
            s.logged = true;
        }
    }

    /// Logs the first recorded layer fault with the stack's refusal, before the
    /// head.
    pub(crate) fn log(&self) {
        let mut s = super::lock(&self.state);
        if !s.logged
            && let Some(Fault::Layer { name, err }) = s.fault().cloned()
        {
            emit_stack_error(&self.meta, &name, &err, AddonMode::Enforce);
            s.logged = true;
        }
    }

    pub(crate) fn fault(&self) -> Option<Fault> {
        super::lock(&self.state).fault().cloned()
    }

    pub(crate) fn is_faulted(&self) -> bool {
        super::lock(&self.state).fault().is_some()
    }
}

impl State {
    fn fault(&self) -> Option<&Fault> {
        self.events.iter().find_map(|e| match e {
            Event::Fault(f) => Some(f),
            Event::Aborted | Event::ClientGone | Event::UpstreamAbandoned => None,
        })
    }
}

/// Whose body a stream is where it enters the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// The client's request body.
    Client,
    /// The upstream's response body.
    Upstream,
    /// The request body the layer at this index passed on, re-validated
    /// for the stage after it.
    Layer(usize),
}

impl Side {
    fn fault(self, st: &StackFlow, e: &BodyError) -> Option<Fault> {
        Some(match (self, e) {
            (_, BodyError::BudgetExhausted) => Fault::Budget,
            (Side::Client, e) => Fault::Client(body_failure(e)),
            (Side::Upstream, _) => Fault::UpstreamBody,
            (Side::Layer(index), BodyError::Invalid(e)) => Fault::Layer {
                name: st.snap.addons[index].name.clone(),
                err: roxy_wasm::LayerError::InvalidRequest(e.to_string()).into(),
            },
            // A cut is the producer's own doing, not a fault, and the
            // service mux records a lane's cap and declared-length faults
            // itself.
            (Side::Layer(_), _) => return None,
        })
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
        // The transport publishes cancellation before cutting lane bodies.
        // Errors observed after that are consequences of the client loss,
        // not a new parse/upstream fault. Any earlier fault still stands.
        if let Some(Err(e)) = &frame
            && !this.st.attribution.is_client_gone()
            && let Some(fault) = this.side.fault(&this.st, e)
        {
            this.st.attribution.record(fault);
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

/// The stack's answer as the transport handler drives it. Dropped before it resolved
/// (the transport handler gave the exchange up: the client's body failed, or the
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

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt as _;

    use super::*;

    #[tokio::test]
    async fn layer_trailer_validation_preserves_prior_faults_and_lane_errors() {
        let kit = crate::testkit::Kit::builder()
            .addon(crate::testkit::AddonDef::test_layer("producer"))
            .start()
            .await;
        for (error, invalid) in [
            (BodyError::Incomplete, false),
            (BodyError::Abandoned, false),
            (
                BodyError::Invalid(ParseError::new(Reason::Trailers, "forbidden")),
                true,
            ),
            (BodyError::LengthMismatch, false),
            (BodyError::TooLarge { limit: 1 }, false),
        ] {
            for prior_fault in [false, true] {
                let (st, _cx, _ends) = crate::addons::test_flow(&kit);
                if prior_fault {
                    st.attribution.record(Fault::Client(ParseError::new(
                        Reason::UnexpectedEof,
                        "client upload",
                    )));
                }
                let (sender, source) = Body::channel(u64::MAX, None);
                let mut body = attributed(&st, Side::Layer(0), source);
                sender.abort(error.clone());
                assert_eq!(body.frame().await.unwrap().unwrap_err(), error);
                match st.attribution.fault() {
                    Some(Fault::Client(_)) => assert!(prior_fault),
                    Some(Fault::Layer { name, err }) => {
                        assert!(!prior_fault && invalid);
                        assert_eq!(name, "producer");
                        assert!(matches!(
                            err,
                            StackError::Layer(roxy_wasm::LayerError::InvalidRequest(_))
                        ));
                    }
                    None => assert!(!prior_fault && !invalid),
                    fault => panic!("unexpected fault: {fault:?}"),
                }
            }
        }
    }

    /// A client's upload cut on its way through two enforcing layers is
    /// the client's: neither layer is blamed, and neither aborted.
    #[tokio::test]
    async fn a_cut_passing_through_two_layers_blames_neither() {
        use super::super::chain::Head;
        let kit = crate::testkit::Kit::builder()
            .addon(crate::testkit::AddonDef::test_layer("a"))
            .addon(crate::testkit::AddonDef::test_layer("b"))
            .start()
            .await;
        let (st, _cx, mut ends) = crate::addons::test_flow(&kit);
        let mut b = ends.layers.pop().unwrap();
        let a = ends.layers.pop().unwrap();
        a.stage.enforcing();
        b.stage.enforcing();
        let (sender, source) = Body::channel(u64::MAX, None);
        let upload = attributed(&st, Side::Client, source);
        let head = || Head::Request(http::Request::new(()).into_parts().0);
        a.req_out.whole(head(), upload);
        let (_, through_a) = b.req_in.head().await.unwrap();
        b.req_out.whole(head(), through_a);
        let (_, at_core) = ends.core.req_in.head().await.unwrap();
        sender.abort(BodyError::Incomplete);
        assert!(at_core.collect().await.is_err());
        let cause = st.cause();
        assert!(matches!(cause.fault, Some(Fault::Client(_))), "{cause:?}");
        assert!(!cause.aborted, "{cause:?}");
        drop(a.req_in);
    }

    /// The four outcomes: a layer's fault names it, a layer's own cut is
    /// its abort, the client's loss and the upstream's failure are theirs.
    #[tokio::test]
    async fn each_cause_is_its_own_and_the_first_stands() {
        let kit = crate::testkit::Kit::builder()
            .addon(crate::testkit::AddonDef::test_layer("a"))
            .start()
            .await;
        let (st, _cx, _ends) = crate::addons::test_flow(&kit);
        st.fail("a", roxy_wasm::LayerError::NoResponse);
        st.attribution.aborted();
        st.attribution.record(Fault::UpstreamBody);
        let cause = st.cause();
        assert!(matches!(cause.fault, Some(Fault::Layer { ref name, .. }) if name == "a"));
        assert!(!cause.aborted, "a cut after a fault is its consequence");

        let (st, _cx, _ends) = crate::addons::test_flow(&kit);
        st.attribution.aborted();
        st.attribution.record(Fault::UpstreamBody);
        let cause = st.cause();
        assert!(cause.aborted);
        assert!(matches!(cause.fault, Some(Fault::UpstreamBody)));

        let (st, _cx, _ends) = crate::addons::test_flow(&kit);
        st.tear_down(crate::addons::CLIENT_GONE);
        st.attribution.aborted();
        let cause = st.cause();
        assert!(cause.client_gone && !cause.aborted, "{cause:?}");

        let (st, _cx, _ends) = crate::addons::test_flow(&kit);
        st.attribution.record(Fault::UpstreamBody);
        assert_eq!(st.fault_reason().as_deref(), Some("upstream_body_failed"));
    }

    #[tokio::test]
    async fn cancellation_body_errors_do_not_replace_the_observed_cause() {
        let kit = crate::testkit::Kit::builder().start().await;
        for side in [Side::Client, Side::Upstream] {
            for prior_fault in [false, true] {
                let (st, _cx, _ends) = crate::addons::test_flow(&kit);
                let (sender, source) = Body::channel(u64::MAX, None);
                let mut body = attributed(&st, side, source);
                if prior_fault {
                    st.fail("s", roxy_wasm::LayerError::NoResponse);
                }
                st.tear_down(crate::addons::CLIENT_GONE);
                sender.abort(BodyError::Incomplete);
                assert!(body.frame().await.unwrap().is_err());
                assert_eq!(
                    st.fault_reason().as_deref(),
                    prior_fault.then_some("layer_error")
                );
                assert_eq!(st.cancellation_reason(), Some("client_gone"));
            }
        }
    }
}
