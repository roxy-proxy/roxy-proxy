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

    /// A written and a discarded response consult the same recorded fault.
    /// A fault recovered by a layer does not taint a successful response.
    pub(crate) fn response_reason(&self, stack: Option<&StackFlow>) -> Option<String> {
        self.reason_from(stack.map(StackFlow::cause).as_ref(), true)
    }

    /// The record's reason, once the exchange is over.
    pub(crate) fn reason(&self, stack: Option<&StackFlow>) -> Option<String> {
        self.reason_from(stack.map(StackFlow::cause).as_ref(), false)
    }

    /// In order: a fault that cut the response, a layer's abort, observed
    /// cancellation, the response's own failure, an upload deadline, then
    /// upstream work nothing waited for. The order is independent of which
    /// adapter finished first. `response_only` stops after the response's
    /// failure.
    fn reason_from(&self, stack: Option<&Cause>, response_only: bool) -> Option<String> {
        let cut = matches!(
            self.response,
            Some(ResponseFailure::Body | ResponseFailure::Write)
        );
        let fault = stack.and_then(|c| c.fault.as_ref()).filter(|_| cut);
        let response = self.response.as_ref().map(|failure| match failure {
            ResponseFailure::Body => "response_body_failed",
            ResponseFailure::Write => "response_write_failed",
            ResponseFailure::Timeout => "response_body_timeout",
            ResponseFailure::ClientGone => "client_gone",
            ResponseFailure::ClientStalled => "client_stalled",
            ResponseFailure::Request(reason) => reason.as_str(),
        });
        if response_only {
            return fault
                .map(|f| f.reason().to_owned())
                .or(response.map(str::to_owned));
        }
        let aborted = stack.is_some_and(|c| c.aborted);
        let cancelled = self.cancellation.as_ref().map(|c| match c {
            Cancellation::ClientGone => "client_gone",
            Cancellation::ClientStalled => "client_stalled",
            Cancellation::Request(reason) => reason.as_str(),
            Cancellation::Stopped => "in_flight_stopped",
            Cancellation::ResponseTimeout => "response_body_timeout",
            Cancellation::Stream => "h2_stream_error",
        });
        // A flow-control timeout tears down with CLIENT_GONE too, but has
        // the more specific transport reason.
        let stalled = matches!(self.response, Some(ResponseFailure::ClientStalled));
        let client_gone = stack.is_some_and(|c| c.client_gone) && !stalled;
        fault
            .map(Fault::reason)
            .or(aborted.then_some(LAYER_ABORTED))
            .or(cancelled)
            .or(client_gone.then_some("client_gone"))
            .or(response)
            .or(self.upload_timed_out.then_some("upstream_body_timeout"))
            .or(stack
                .is_some_and(|c| c.upstream_abandoned)
                .then_some(LAYER_ABORTED))
            .map(str::to_owned)
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
