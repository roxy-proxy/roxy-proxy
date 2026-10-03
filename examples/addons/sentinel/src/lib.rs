//! An inspect-sentinel for roxy (DESIGN.md §11.7): blocks LLM tool calls by
//! policy.
//!
//! * **Requests** to the Anthropic Messages, OpenAI Chat Completions and
//!   OpenAI Responses APIs: declared tools the policy denies are removed
//!   from `tools` (so the model cannot call them), and a request whose
//!   history contains a denied call (one the agent made anyway) is refused.
//! * **Responses**: a denied tool call is replaced by a text refusal the
//!   agent can act on (§11.7 `reject`), in plain JSON responses and in
//!   streamed Anthropic responses, where `tool_use` blocks are withheld
//!   until judged while text streams through.
//! * Every denial is recorded with `flow.record("sentinel_decision", ..,
//!   audit: true)`. After `terminate_after` denials, the principal is
//!   quarantined with `flow.terminate`.
//!
//! Anything else (other paths, other methods) passes through untouched, as
//! does any response with nothing to deny: byte for byte.
//!
//! The decision itself is [`judge::judge`]; that is the one function to
//! change to judge with a model instead of regexes.

pub mod judge;
pub mod sse;
pub mod tools;

use std::time::Duration;

use roxy_addon::flow::{self, Scope};
use roxy_addon::prelude::*;
use serde_json::{Value, json};

use judge::{Policy, ToolCall, Verdict};
use tools::Api;

/// The sentinel layer.
pub struct Sentinel {
    policy: std::rc::Rc<Policy>,
    /// Quarantine the principal after this many denials (`None`: never).
    terminate_after: Option<u64>,
    terminate_ttl: Duration,
    /// Largest JSON body the sentinel reads to inspect.
    max_body_bytes: usize,
}

impl Layer for Sentinel {
    fn init(config: &str) -> Result<Self, String> {
        let config: Value = serde_json::from_str(config).map_err(|e| format!("config: {e}"))?;
        Ok(Self {
            policy: std::rc::Rc::new(Policy::from_config(&config)?),
            terminate_after: config["terminate_after"].as_u64().filter(|n| *n > 0),
            terminate_ttl: Duration::from_secs(
                config["terminate_ttl_secs"].as_u64().unwrap_or(3600),
            ),
            max_body_bytes: config["max_body_bytes"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(8 * 1024 * 1024),
        })
    }

    fn handle(&mut self, req: Request, next: Next) -> Response {
        let Some(api) = Api::detect(&req.method, req.path()) else {
            return next.run(req);
        };
        match self.inspect_request(api, req) {
            Ok(req) => self.inspect_response(api, next.run(req)),
            Err(refusal) => refusal,
        }
    }
}

roxy_addon::export!(Sentinel);

impl Sentinel {
    /// Judges a call, recording (and counting) a denial.
    fn deny(&self, api: Api, direction: &str, call: &ToolCall) -> Option<String> {
        match judge::judge(&self.policy, call) {
            Verdict::Allow => None,
            Verdict::Deny { reason } => {
                self.on_denied(api, direction, call, &reason);
                Some(reason)
            }
        }
    }

    fn on_denied(&self, api: Api, direction: &str, call: &ToolCall, reason: &str) {
        record_decision(api, direction, call, reason);
        if let Some(limit) = self.terminate_after {
            count_violation(limit, self.terminate_ttl);
        }
    }

    /// Returns the request to pass on (possibly rewritten), or the response
    /// that refuses it.
    fn inspect_request(&self, api: Api, mut req: Request) -> Result<Request, Response> {
        let refuse = |status: u16, msg: &str| Response::json(status, api.error_body(msg));
        if req
            .headers
            .get_str("content-encoding")
            .is_some_and(|e| !e.eq_ignore_ascii_case("identity"))
        {
            return Err(refuse(415, "sentinel: compressed request bodies cannot be inspected"));
        }
        // Ask for an uncompressed response, so it can be inspected.
        req.headers.set("accept-encoding", "identity");

        let raw = match std::mem::take(&mut req.body).read_to_end(self.max_body_bytes) {
            Ok(raw) => raw,
            Err(BodyError::TooLarge { .. }) => {
                return Err(refuse(413, "sentinel: request too large to inspect"));
            }
            Err(e) => panic!("request body failed: {e}"),
        };
        let Ok(mut body) = serde_json::from_slice::<Value>(&raw) else {
            // Not JSON: the API will reject it; nothing to inspect.
            return Ok(req.with_body(raw));
        };

        if body["stream"] == true && api != Api::AnthropicMessages {
            return Err(refuse(
                400,
                "sentinel: streamed responses are only inspected for the Anthropic Messages API; \
                 set \"stream\": false",
            ));
        }

        // A denied call in the history was executed without the sentinel's
        // consent (it would have been replaced): refuse the request.
        for call in tools::history_calls(api, &body) {
            if let Some(reason) = self.deny(api, "request", &call) {
                return Err(refuse(
                    403,
                    &format!("sentinel: the conversation contains a blocked tool call: {reason}"),
                ));
            }
        }

        // Remove declared tools the policy denies, so the model never sees
        // them.
        let removed = tools::strip_declared_tools(api, &mut body, |call| {
            match judge::judge(&self.policy, call) {
                Verdict::Allow => None,
                Verdict::Deny { reason } => Some(reason),
            }
        });
        if removed.is_empty() {
            return Ok(req.with_body(raw));
        }
        for (name, reason) in &removed {
            let call = ToolCall {
                name: name.clone(),
                arguments: "{}".to_owned(),
            };
            record_decision(api, "declaration", &call, reason);
        }
        Ok(req.with_body(body.to_string()))
    }

    fn inspect_response(&self, api: Api, resp: Response) -> Response {
        if resp
            .headers
            .get_str("content-encoding")
            .is_some_and(|e| !e.eq_ignore_ascii_case("identity"))
        {
            // Asked for identity and did not get it: cannot inspect, so
            // fail closed.
            return Response::json(
                502,
                api.error_body("sentinel: compressed response cannot be inspected"),
            );
        }
        let content_type = resp.headers.get_str("content-type").unwrap_or("");
        if content_type.starts_with("text/event-stream") {
            if api != Api::AnthropicMessages {
                return Response::json(
                    502,
                    api.error_body("sentinel: this streamed response cannot be inspected"),
                );
            }
            let policy = self.policy.clone();
            let terminate_after = self.terminate_after;
            let ttl = self.terminate_ttl;
            let deny: sse::DenyFn = Box::new(move |call| match judge::judge(&policy, call) {
                Verdict::Allow => None,
                Verdict::Deny { reason } => {
                    record_decision(api, "response", call, &reason);
                    if let Some(limit) = terminate_after {
                        count_violation(limit, ttl);
                    }
                    Some(reason)
                }
            });
            return resp.map_body(|b| b.pipe(sse::Withholder::new(deny)));
        }
        if !content_type.contains("json") || !(200..300).contains(&resp.status) {
            return resp;
        }

        let Response {
            status,
            headers,
            body,
        } = resp;
        let raw = match body.read_to_end(self.max_body_bytes) {
            Ok(raw) => raw,
            Err(BodyError::TooLarge { .. }) => {
                return Response::json(
                    502,
                    api.error_body("sentinel: response too large to inspect"),
                );
            }
            Err(e) => panic!("response body failed: {e}"),
        };
        let unchanged = |raw: Vec<u8>| Response {
            status,
            headers: headers.clone(),
            body: raw.into(),
        };
        let Ok(mut json) = serde_json::from_slice::<Value>(&raw) else {
            return unchanged(raw);
        };
        let denied = tools::rewrite_response(api, &mut json, |call| self.deny(api, "response", call));
        if denied.is_empty() {
            unchanged(raw)
        } else {
            unchanged(json.to_string().into_bytes())
        }
    }
}

fn record_decision(api: Api, direction: &str, call: &ToolCall, reason: &str) {
    let event = json!({
        "api": api.name(),
        "direction": direction,
        "tool": call.name,
        "arguments": call.arguments,
        "verdict": "deny",
        "reason": reason,
    });
    flow::record("sentinel_decision", &event.to_string(), true);
}

/// Counts a denial against the principal and quarantines it at `limit`.
fn count_violation(limit: u64, ttl: Duration) {
    let key = format!("violations:{}", flow::principal_key());
    let count = flow::state_get(&key)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        + 1;
    // A full store is not a reason to stop judging; the count just stops
    // growing.
    let _ = flow::state_put(&key, &count.to_string(), Some(ttl));
    if count >= limit {
        let reason = format!("{count} blocked tool calls");
        let took = flow::terminate(Scope::Principal, &reason, Some(ttl));
        let event = json!({"principal": flow::principal_key(), "violations": count, "quarantined": took});
        flow::record("sentinel_terminate", &event.to_string(), true);
    }
}
