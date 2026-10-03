//! Withholding `tool_use` blocks in a streamed Anthropic Messages response
//! (DESIGN.md §11.1, "withhold until cleared").
//!
//! Text streams to the client as it arrives. When a `tool_use` content
//! block starts, its events are held back until the block is complete; then
//! the call is judged and the held events are either released unchanged or
//! replaced by a text block carrying the refusal. Events are passed through
//! byte for byte whenever nothing is denied.

use roxy_addon::ChunkTransform;
use serde_json::{Value, json};

use crate::judge::ToolCall;
use crate::tools::refusal_text;

/// Returns the denial reason for a call, or `None` to allow it.
pub type DenyFn = Box<dyn FnMut(&ToolCall) -> Option<String>>;

struct Held {
    index: Value,
    name: String,
    input_json: String,
    start_input: Value,
    raw: Vec<u8>,
}

/// The withholding transform for an Anthropic `text/event-stream` body.
pub struct Withholder {
    deny: DenyFn,
    /// Bytes of an incomplete event.
    pending: Vec<u8>,
    held: Option<Held>,
    allowed: usize,
    denied: usize,
}

impl Withholder {
    /// A withholder that judges each `tool_use` block with `deny`.
    pub fn new(deny: DenyFn) -> Self {
        Self {
            deny,
            pending: Vec::new(),
            held: None,
            allowed: 0,
            denied: 0,
        }
    }

    /// Handles one complete event (including its blank-line terminator),
    /// appending what should be sent on to `out`.
    fn event(&mut self, raw: &[u8], out: &mut Vec<u8>) {
        let Some(data) = event_data(raw) else {
            self.emit(raw, out);
            return;
        };
        let kind = data["type"].as_str().unwrap_or("");

        if kind == "content_block_start" && data["content_block"]["type"] == "tool_use" {
            self.held = Some(Held {
                index: data["index"].clone(),
                name: data["content_block"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                input_json: String::new(),
                start_input: data["content_block"]["input"].clone(),
                raw: raw.to_vec(),
            });
            return;
        }

        if let Some(held) = &mut self.held
            && data["index"] == held.index
        {
            match kind {
                "content_block_delta" => {
                    if let Some(part) = data["delta"]["partial_json"].as_str() {
                        held.input_json.push_str(part);
                    }
                    held.raw.extend_from_slice(raw);
                    return;
                }
                "content_block_stop" => {
                    let held = self.held.take().expect("held block");
                    self.finish_block(held, raw, out);
                    return;
                }
                _ => {}
            }
        }

        if kind == "message_delta"
            && data["delta"]["stop_reason"] == "tool_use"
            && self.denied > 0
            && self.allowed == 0
        {
            let mut data = data;
            data["delta"]["stop_reason"] = json!("end_turn");
            write_event(out, "message_delta", &data);
            return;
        }

        self.emit(raw, out);
    }

    fn finish_block(&mut self, held: Held, stop_raw: &[u8], out: &mut Vec<u8>) {
        let arguments = if held.input_json.trim().is_empty() {
            match &held.start_input {
                Value::Null => "{}".to_owned(),
                v => v.to_string(),
            }
        } else {
            // Normalise to compact JSON so patterns see the same text as in
            // a non-streaming response.
            serde_json::from_str::<Value>(&held.input_json)
                .map_or(held.input_json.clone(), |v| v.to_string())
        };
        let call = ToolCall {
            name: held.name,
            arguments,
        };
        match (self.deny)(&call) {
            None => {
                self.allowed += 1;
                out.extend_from_slice(&held.raw);
                out.extend_from_slice(stop_raw);
            }
            Some(reason) => {
                self.denied += 1;
                let index = held.index;
                write_event(
                    out,
                    "content_block_start",
                    &json!({"type": "content_block_start", "index": index,
                            "content_block": {"type": "text", "text": ""}}),
                );
                write_event(
                    out,
                    "content_block_delta",
                    &json!({"type": "content_block_delta", "index": index,
                            "delta": {"type": "text_delta", "text": refusal_text(&call.name, &reason)}}),
                );
                write_event(
                    out,
                    "content_block_stop",
                    &json!({"type": "content_block_stop", "index": index}),
                );
            }
        }
    }

    fn emit(&self, raw: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(raw);
    }
}

impl ChunkTransform for Withholder {
    fn chunk(&mut self, chunk: Vec<u8>) -> Vec<u8> {
        self.pending.extend_from_slice(&chunk);
        let mut out = Vec::new();
        while let Some(end) = find_event_end(&self.pending) {
            let raw: Vec<u8> = self.pending.drain(..end).collect();
            self.event(&raw, &mut out);
        }
        out
    }

    fn finish(&mut self) -> Vec<u8> {
        // A stream that ends inside a tool_use block never completed it:
        // drop it rather than release an unjudged call.
        self.held = None;
        std::mem::take(&mut self.pending)
    }
}

/// The end (exclusive, including the blank line) of the first complete
/// event in `buf`.
fn find_event_end(buf: &[u8]) -> Option<usize> {
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The JSON `data:` of an event, if it has one.
fn event_data(raw: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(raw).ok()?;
    let data: String = text
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim_start)
        .collect::<Vec<_>>()
        .join("\n");
    if data.is_empty() {
        return None;
    }
    serde_json::from_str(&data).ok()
}

fn write_event(out: &mut Vec<u8>, name: &str, data: &Value) {
    out.extend_from_slice(format!("event: {name}\ndata: {data}\n\n").as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(name: &str, data: &Value) -> String {
        format!("event: {name}\ndata: {data}\n\n")
    }

    fn stream(tool: &str, args: &str) -> String {
        [
            ev(
                "message_start",
                &json!({"type": "message_start", "message": {"id": "m"}}),
            ),
            ev(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 0,
                "content_block": {"type": "text", "text": ""}}),
            ),
            ev(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 0,
                "delta": {"type": "text_delta", "text": "Running it."}}),
            ),
            ev(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 0}),
            ),
            ev(
                "content_block_start",
                &json!({"type": "content_block_start", "index": 1,
                "content_block": {"type": "tool_use", "id": "t1", "name": tool, "input": {}}}),
            ),
            ev(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": &args[..args.len() / 2]}}),
            ),
            ev(
                "content_block_delta",
                &json!({"type": "content_block_delta", "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": &args[args.len() / 2..]}}),
            ),
            ev(
                "content_block_stop",
                &json!({"type": "content_block_stop", "index": 1}),
            ),
            ev(
                "message_delta",
                &json!({"type": "message_delta",
                "delta": {"stop_reason": "tool_use"}}),
            ),
            ev("message_stop", &json!({"type": "message_stop"})),
        ]
        .concat()
    }

    fn run(input: &str, chunk: usize, deny: DenyFn) -> String {
        let mut w = Withholder::new(deny);
        let mut out = Vec::new();
        for piece in input.as_bytes().chunks(chunk) {
            out.extend(w.chunk(piece.to_vec()));
        }
        out.extend(w.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn allowed_stream_is_unchanged() {
        let input = stream("get_weather", r#"{"city":"Paris"}"#);
        for chunk in [1, 7, 64, 4096] {
            assert_eq!(run(&input, chunk, Box::new(|_| None)), input);
        }
    }

    #[test]
    fn denied_tool_use_becomes_text() {
        let input = stream("bash", r#"{"cmd":"rm -rf /"}"#);
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let s = seen.clone();
        let out = run(
            &input,
            13,
            Box::new(move |c| {
                s.borrow_mut().push(c.clone());
                Some("no".into())
            }),
        );
        assert!(!out.contains("tool_use\""), "{out}");
        assert!(out.contains("[sentinel] The call to tool `bash` was blocked"));
        assert!(out.contains(r#""stop_reason":"end_turn""#));
        assert!(out.contains("Running it."));
        assert_eq!(
            seen.borrow().as_slice(),
            &[ToolCall {
                name: "bash".into(),
                arguments: r#"{"cmd":"rm -rf /"}"#.into()
            }]
        );
    }

    #[test]
    fn unfinished_tool_use_is_dropped() {
        let input = stream("bash", "{}");
        let cut = input
            .find("content_block_stop\ndata: {\"index\":1")
            .unwrap_or(input.len() - 60);
        let out = run(&input[..cut], 5, Box::new(|_| None));
        assert!(!out.contains("tool_use"), "{out}");
    }
}
