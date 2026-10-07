//! Holds each user to a token quota kept by a quota service.
//!
//! Before a model call leaves, the layer asks the `quota-check` endpoint
//! whether the user's bucket holds anything; a refusal is answered here
//! with a `429` that says when to try again.
//! After the model's response has streamed through, it reports the tokens
//! the response said it used to `quota-report`. The layer reads the usage
//! Anthropic Messages responses carry (`message_start` and `message_delta`
//! events of a stream, or `usage` of a JSON response) and changes nothing.
//!
//! The user is the flow's `user:<name>` tag when a layer above set one, and
//! otherwise the client IP, so the layer works alone or below an
//! authenticating layer.
//!
//! ```yaml
//! addons:
//!   - name: token-quota
//!     kind: wasm
//!     path: /etc/roxy/addons/token_quota.wasm
//!     when: method == POST and path == "/v1/messages"
//!     capabilities: [endpoints, record]
//!     endpoints:
//!       quota-check:  { url: "http://quota-board:8090/check",  private_ok: true }
//!       quota-report: { url: "http://quota-board:8090/report", private_ok: true }
//! ```

use roxy_addon::prelude::*;
use serde::Deserialize;
use serde_json::Value;

const MAX_REPLY: usize = 64 * 1024;
/// A non-streamed model response is read whole to find its `usage`.
const MAX_RESPONSE: usize = 8 * 1024 * 1024;
/// The longest SSE line kept while waiting for its end; a stream without
/// newlines is passed through unread rather than buffered.
const MAX_LINE: usize = 1024 * 1024;

#[derive(Deserialize)]
struct Allowance {
    allowed: bool,
    available: i64,
    capacity: u64,
    refill_per_sec: f64,
    retry_in: u64,
}

pub struct TokenQuota;

impl Layer for TokenQuota {
    fn init(_config: &str) -> Result<Self, String> {
        Ok(Self)
    }

    fn handle(&mut self, req: Request, next: Next) -> Response {
        let user = principal();
        let allowance = check(&user);
        if !allowance.allowed {
            flow::record(
                "quota",
                &serde_json::json!({
                    "result": "refused", "user": user,
                    "available": allowance.available, "capacity": allowance.capacity,
                })
                .to_string(),
                false,
            );
            return over_quota(&allowance);
        }

        let resp = next.run(req);
        if resp.status != 200 {
            return resp;
        }
        let streamed = resp
            .headers
            .get_str("content-type")
            .is_some_and(|ct| ct.starts_with("text/event-stream"));
        if streamed {
            resp.map_body(|b| b.pipe(UsageMeter::new(user)))
        } else {
            let Response {
                status,
                headers,
                body,
            } = resp;
            let bytes = body.read_to_end(MAX_RESPONSE).expect("model response");
            let usage = Usage::from_message(&bytes);
            report(&user, usage);
            Response {
                status,
                headers,
                body: Body::from_bytes(bytes),
            }
        }
    }
}

roxy_addon::export!(TokenQuota);

/// Who is spending: the `user:` tag an authenticating layer above set, or
/// the client IP.
fn principal() -> String {
    let info = flow::current();
    info.tags
        .iter()
        .find_map(|t| t.strip_prefix("user:"))
        .map_or_else(|| format!("ip:{}", info.principal.client_ip), str::to_owned)
}

fn check(user: &str) -> Allowance {
    let req = Request::new("POST", "/")
        .with_header("content-type", "application/json")
        .with_body(serde_json::json!({"user": user}).to_string());
    let resp = call_endpoint("quota-check", req).expect("quota service unreachable");
    assert_eq!(resp.status, 200, "quota service answered {}", resp.status);
    let body = resp.body.read_to_end(MAX_REPLY).expect("quota reply");
    serde_json::from_slice(&body).expect("quota reply is not an allowance")
}

fn report(user: &str, usage: Usage) {
    let json = serde_json::json!({
        "user": user,
        "input_tokens": usage.input,
        "output_tokens": usage.output,
    });
    let req = Request::new("POST", "/")
        .with_header("content-type", "application/json")
        .with_body(json.to_string());
    let resp = call_endpoint("quota-report", req).expect("quota service unreachable");
    assert_eq!(resp.status, 200, "quota service answered {}", resp.status);
    flow::record("quota", &json.to_string(), false);
}

/// An Anthropic-shaped rate-limit error, so SDK clients raise their usual
/// exception, with `retry-after` saying when the bucket is positive again.
fn over_quota(a: &Allowance) -> Response {
    let message = format!(
        "token bucket empty ({} tokens, refills {}/s); try again in {}s",
        a.capacity, a.refill_per_sec, a.retry_in
    );
    Response::json(
        429,
        serde_json::json!({
            "type": "error",
            "error": {"type": "rate_limit_error", "message": message},
        })
        .to_string(),
    )
    .with_header("retry-after", a.retry_in.max(1).to_string())
}

/// The tokens a response reported. Anthropic sends `input_tokens` with the
/// head and a running `output_tokens` total, so the last value of each wins.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    input: u64,
    output: u64,
}

impl Usage {
    /// Takes whatever a `usage` object knows.
    fn absorb(&mut self, usage: &Value) {
        if let Some(n) = usage.get("input_tokens").and_then(Value::as_u64) {
            self.input = n;
        }
        if let Some(n) = usage.get("output_tokens").and_then(Value::as_u64) {
            self.output = n;
        }
    }

    /// The usage of one streamed event, if it carries any.
    fn absorb_event(&mut self, event: &Value) {
        match event.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                if let Some(u) = event.pointer("/message/usage") {
                    self.absorb(u);
                }
            }
            Some("message_delta") => {
                if let Some(u) = event.get("usage") {
                    self.absorb(u);
                }
            }
            _ => {}
        }
    }

    /// The usage of a whole (non-streamed) message.
    fn from_message(bytes: &[u8]) -> Self {
        let mut usage = Self::default();
        if let Ok(message) = serde_json::from_slice::<Value>(bytes)
            && let Some(u) = message.get("usage")
        {
            usage.absorb(u);
        }
        usage
    }
}

/// Reads the usage out of an SSE stream as it passes, unchanged, and
/// reports it when the stream is done with. The report is made on drop, so
/// a stream the client or the model cut short is charged for what it had
/// reported by then.
pub struct UsageMeter {
    user: String,
    usage: Usage,
    /// The unterminated tail of the last chunk: a line can straddle chunks.
    partial: Vec<u8>,
}

impl UsageMeter {
    fn new(user: String) -> Self {
        Self {
            user,
            usage: Usage::default(),
            partial: Vec::new(),
        }
    }

    /// Reads whatever the tail holds, so a final line without a newline
    /// counts.
    fn flush_tail(&mut self) {
        let tail = std::mem::take(&mut self.partial);
        if !tail.is_empty() {
            self.line(&tail);
        }
    }

    fn line(&mut self, line: &[u8]) {
        let Some(data) = line.strip_prefix(b"data:") else {
            return;
        };
        if let Ok(event) = serde_json::from_slice::<Value>(data) {
            self.usage.absorb_event(&event);
        }
    }
}

impl ChunkTransform for UsageMeter {
    fn chunk(&mut self, chunk: Vec<u8>) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.partial);
        buf.extend_from_slice(&chunk);
        let mut rest = buf.as_slice();
        while let Some(nl) = rest.iter().position(|&b| b == b'\n') {
            let line = rest[..nl].strip_suffix(b"\r").unwrap_or(&rest[..nl]);
            self.line(line);
            rest = &rest[nl + 1..];
        }
        if rest.len() <= MAX_LINE {
            self.partial = rest.to_vec();
        }
        chunk
    }
}

impl Drop for UsageMeter {
    fn drop(&mut self) {
        self.flush_tail();
        report(&self.user, self.usage);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM: &[u8] = b"event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n\
event: message_delta\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":40}}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n\n";

    /// Feeds the stream in chunks of `size` and returns the usage read and
    /// the bytes passed on.
    fn meter(size: usize) -> (Usage, Vec<u8>) {
        let mut m = UsageMeter::new("alice".into());
        let mut out = Vec::new();
        for c in STREAM.chunks(size) {
            out.extend(m.chunk(c.to_vec()));
        }
        m.flush_tail();
        let usage = m.usage;
        // Dropping the meter would report to an endpoint no test has.
        std::mem::forget(m);
        (usage, out)
    }

    #[test]
    fn reads_usage_across_any_chunking_and_passes_bytes_through() {
        for size in [1, 7, 64, STREAM.len()] {
            let (usage, out) = meter(size);
            assert_eq!(
                usage,
                Usage {
                    input: 25,
                    output: 40
                },
                "chunk size {size}"
            );
            assert_eq!(out, STREAM, "chunk size {size}");
        }
    }

    #[test]
    fn last_output_total_wins_and_input_survives() {
        let mut u = Usage::default();
        u.absorb_event(&serde_json::json!({
            "type": "message_start", "message": {"usage": {"input_tokens": 9, "output_tokens": 1}}
        }));
        u.absorb_event(
            &serde_json::json!({"type": "message_delta", "usage": {"output_tokens": 12}}),
        );
        u.absorb_event(
            &serde_json::json!({"type": "message_delta", "usage": {"output_tokens": 30}}),
        );
        assert_eq!(
            u,
            Usage {
                input: 9,
                output: 30
            }
        );
    }

    #[test]
    fn whole_message_usage() {
        let msg = br#"{"id":"m","usage":{"input_tokens":11,"output_tokens":22}}"#;
        assert_eq!(
            Usage::from_message(msg),
            Usage {
                input: 11,
                output: 22
            }
        );
        assert_eq!(Usage::from_message(b"not json"), Usage::default());
    }

    #[test]
    fn non_usage_lines_are_ignored() {
        let mut m = UsageMeter::new("alice".into());
        m.chunk(b"event: ping\ndata: {\"type\":\"ping\"}\n\n: comment\ndata: not json\n".to_vec());
        assert_eq!(m.usage, Usage::default());
        assert_eq!(m.partial, b"");
        std::mem::forget(m);
    }

    #[test]
    fn an_endless_line_is_passed_through_but_not_kept() {
        let mut m = UsageMeter::new("alice".into());
        let chunk = vec![b'x'; MAX_LINE + 1];
        assert_eq!(m.chunk(chunk.clone()), chunk);
        assert_eq!(m.partial, b"");
        std::mem::forget(m);
    }
}
