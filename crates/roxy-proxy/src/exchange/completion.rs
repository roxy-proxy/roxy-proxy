//! Facts collected while the wire action and the rest of the exchange
//! finish. Adapters report what happened; final attribution is selected
//! after reclamation, once faults, cancellations and upload outcomes are
//! all available. A policy or validation reason already in the record wins.

use roxy_http::{BodyError, Reason};

use super::WriteFailure;
use crate::addons::StackFlow;
use crate::addons::attribution::{Cause, Fault, LAYER_ABORTED};

#[derive(Default)]
pub(crate) struct Completion {
    response: Option<ResponseFailure>,
    cancellation: Option<Cancellation>,
    pub(crate) upload_timed_out: bool,
}

enum ResponseFailure {
    Body,
    Write,
    Timeout,
    ClientGone,
    ClientStalled,
    Request(Reason),
}

enum Cancellation {
    ClientGone,
    ClientStalled,
    Request(Reason),
    Stopped,
    ResponseTimeout,
    Stream,
}

impl Completion {
    pub(crate) fn drained(&mut self, error: &BodyError) {
        self.response = Some(if *error == BodyError::Timeout {
            ResponseFailure::Timeout
        } else {
            ResponseFailure::Body
        });
    }

    pub(crate) fn write_failed(&mut self, error: &WriteFailure) {
        self.response = match error {
            WriteFailure::Stopped => None,
            WriteFailure::ClientGone(_) => Some(ResponseFailure::ClientGone),
            WriteFailure::ClientStalled => Some(ResponseFailure::ClientStalled),
            WriteFailure::UpstreamStalled => Some(ResponseFailure::Timeout),
            WriteFailure::Request(e) => Some(ResponseFailure::Request(e.reason)),
            WriteFailure::Io(_) => Some(ResponseFailure::Write),
        };
    }

    pub(crate) fn cancelled(&mut self, error: &WriteFailure) {
        self.cancellation = Some(match error {
            WriteFailure::ClientGone(_) => Cancellation::ClientGone,
            WriteFailure::ClientStalled => Cancellation::ClientStalled,
            WriteFailure::Request(e) => Cancellation::Request(e.reason),
            WriteFailure::Stopped => Cancellation::Stopped,
            WriteFailure::UpstreamStalled => Cancellation::ResponseTimeout,
            WriteFailure::Io(_) => Cancellation::Stream,
        });
    }

    /// Why the response failed, if it did. A written and a discarded
    /// response consult the same recorded fault; a fault a layer recovered
    /// from does not taint a successful response.
    pub(crate) fn response_reason(&self, stack: Option<&StackFlow>) -> Option<String> {
        let cause = stack.map(StackFlow::cause);
        self.fault_behind_cut(cause.as_ref())
            .or(self.response_failure())
            .map(str::to_owned)
    }

    /// The record's reason, once the exchange is over. In order: a fault
    /// that cut the response, a layer's abort, observed cancellation, the
    /// response's own failure, an upload deadline, then upstream work
    /// nothing waited for. The order is independent of which adapter
    /// finished first.
    pub(crate) fn reason(&self, stack: Option<&StackFlow>) -> Option<String> {
        let cause = stack.map(StackFlow::cause);
        let cause = cause.as_ref();
        // A flow-control timeout tears down with CLIENT_GONE too, but has
        // the more specific transport reason.
        let stalled = matches!(self.response, Some(ResponseFailure::ClientStalled));
        self.fault_behind_cut(cause)
            .or(cause.is_some_and(|c| c.aborted).then_some(LAYER_ABORTED))
            .or(self.cancellation_reason())
            .or((cause.is_some_and(|c| c.client_gone) && !stalled).then_some("client_gone"))
            .or(self.response_failure())
            .or(self.upload_timed_out.then_some("upstream_body_timeout"))
            .or(cause
                .is_some_and(|c| c.upstream_abandoned)
                .then_some(LAYER_ABORTED))
            .map(str::to_owned)
    }

    /// The stack's fault, when the response body failed or could not be
    /// written: that is what cut it.
    fn fault_behind_cut<'a>(&self, cause: Option<&'a Cause>) -> Option<&'a str> {
        let cut = matches!(
            self.response,
            Some(ResponseFailure::Body | ResponseFailure::Write)
        );
        cause
            .and_then(|c| c.fault.as_ref())
            .filter(|_| cut)
            .map(Fault::reason)
    }

    fn response_failure(&self) -> Option<&str> {
        Some(match self.response.as_ref()? {
            ResponseFailure::Body => "response_body_failed",
            ResponseFailure::Write => "response_write_failed",
            ResponseFailure::Timeout => "response_body_timeout",
            ResponseFailure::ClientGone => "client_gone",
            ResponseFailure::ClientStalled => "client_stalled",
            ResponseFailure::Request(reason) => reason.as_str(),
        })
    }

    fn cancellation_reason(&self) -> Option<&str> {
        Some(match self.cancellation.as_ref()? {
            Cancellation::ClientGone => "client_gone",
            Cancellation::ClientStalled => "client_stalled",
            Cancellation::Request(reason) => reason.as_str(),
            Cancellation::Stopped => "in_flight_stopped",
            Cancellation::ResponseTimeout => "response_body_timeout",
            Cancellation::Stream => "h2_stream_error",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Discarding versus writing, and the order in which cancellation and
    /// body failure are reported, cannot change the final cause.
    #[tokio::test]
    async fn completion_attribution_is_independent_of_consumption_and_observation_order() {
        let kit = crate::testkit::Kit::builder().start().await;
        for discarded in [false, true] {
            for cancel_first in [false, true] {
                for fault in [false, true] {
                    for policy in [false, true] {
                        let (st, mut cx, _ends) = crate::addons::test_flow(&kit);
                        if policy {
                            cx.record.reason = Some("policy_failure".to_owned());
                        }
                        if fault {
                            st.fail("s", roxy_wasm::LayerError::NoResponse);
                        }
                        let cancelled = WriteFailure::ClientGone("reset".to_owned());
                        if cancel_first {
                            cx.completion.cancelled(&cancelled);
                        }
                        if discarded {
                            cx.completion.drained(&BodyError::Incomplete);
                        } else {
                            cx.completion
                                .write_failed(&WriteFailure::Io("cut".to_owned()));
                        }
                        if !cancel_first {
                            cx.completion.cancelled(&cancelled);
                        }
                        st.fold_into(&mut cx);
                        let expected = if policy {
                            "policy_failure"
                        } else if fault {
                            "layer_error"
                        } else {
                            "client_gone"
                        };
                        assert_eq!(cx.record.reason.as_deref(), Some(expected));
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn a_recovered_fault_does_not_fail_a_successful_response() {
        let kit = crate::testkit::Kit::builder().start().await;
        let (st, mut cx, _ends) = crate::addons::test_flow(&kit);
        st.fail("s", roxy_wasm::LayerError::NoResponse);
        st.fold_into(&mut cx);
        assert!(cx.record.reason.is_none());
    }
}
