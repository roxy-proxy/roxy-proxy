//! Finding tool calls in LLM API bodies, and rewriting bodies whose calls
//! were denied. Pure JSON manipulation: nothing here talks to the host.

use serde_json::{Map, Value, json};

use crate::judge::ToolCall;

/// The LLM APIs this sentinel understands, recognised by request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// Anthropic Messages (`POST /v1/messages`).
    AnthropicMessages,
    /// OpenAI Chat Completions (`POST /v1/chat/completions`).
    OpenAiChat,
    /// OpenAI Responses (`POST /v1/responses`).
    OpenAiResponses,
}

impl Api {
    /// Recognises an API call by method and path.
    pub fn detect(method: &str, path: &str) -> Option<Api> {
        if method != "POST" {
            return None;
        }
        match path.trim_end_matches('/') {
            p if p.ends_with("/v1/messages") => Some(Api::AnthropicMessages),
            p if p.ends_with("/v1/chat/completions") => Some(Api::OpenAiChat),
            p if p.ends_with("/v1/responses") => Some(Api::OpenAiResponses),
            _ => None,
        }
    }

    /// Name used in records.
    pub fn name(self) -> &'static str {
        match self {
            Api::AnthropicMessages => "anthropic.messages",
            Api::OpenAiChat => "openai.chat",
            Api::OpenAiResponses => "openai.responses",
        }
    }

    /// An error body in this API's shape, for denying a request.
    pub fn error_body(self, message: &str) -> String {
        match self {
            Api::AnthropicMessages => json!({
                "type": "error",
                "error": {"type": "permission_error", "message": message},
            }),
            Api::OpenAiChat | Api::OpenAiResponses => json!({
                "error": {
                    "message": message,
                    "type": "permission_error",
                    "code": "tool_call_denied",
                },
            }),
        }
        .to_string()
    }
}

fn args_string(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "{}".to_owned(),
        // OpenAI sends arguments as a JSON string already.
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Tool calls the agent has already made, in a request's conversation
/// history (assistant `tool_use` blocks, `tool_calls`, `function_call`
/// items).
pub fn history_calls(api: Api, body: &Value) -> Vec<ToolCall> {
    let mut calls = Vec::new();
    match api {
        Api::AnthropicMessages => {
            for msg in body["messages"].as_array().into_iter().flatten() {
                for block in msg["content"].as_array().into_iter().flatten() {
                    if block["type"] == "tool_use"
                        && let Some(name) = str_field(block, "name")
                    {
                        calls.push(ToolCall {
                            name,
                            arguments: args_string(block.get("input")),
                        });
                    }
                }
            }
        }
        Api::OpenAiChat => {
            for msg in body["messages"].as_array().into_iter().flatten() {
                for tc in msg["tool_calls"].as_array().into_iter().flatten() {
                    if let Some(name) = str_field(&tc["function"], "name") {
                        calls.push(ToolCall {
                            name,
                            arguments: args_string(tc["function"].get("arguments")),
                        });
                    }
                }
            }
        }
        Api::OpenAiResponses => {
            for item in body["input"].as_array().into_iter().flatten() {
                if item["type"] == "function_call"
                    && let Some(name) = str_field(item, "name")
                {
                    calls.push(ToolCall {
                        name,
                        arguments: args_string(item.get("arguments")),
                    });
                }
            }
        }
    }
    calls
}

/// The name of a tool declared in a request's `tools` list.
fn declared_name(api: Api, tool: &Value) -> Option<String> {
    match api {
        Api::AnthropicMessages | Api::OpenAiResponses => str_field(tool, "name"),
        Api::OpenAiChat => str_field(&tool["function"], "name"),
    }
}

/// Removes declared tools for which `deny` returns a reason, so the model
/// cannot call them. Returns the removed tools' names and reasons.
pub fn strip_declared_tools(
    api: Api,
    body: &mut Value,
    mut deny: impl FnMut(&ToolCall) -> Option<String>,
) -> Vec<(String, String)> {
    let mut removed = Vec::new();
    if let Some(tools) = body.get_mut("tools").and_then(Value::as_array_mut) {
        tools.retain(|tool| {
            let Some(name) = declared_name(api, tool) else {
                return true;
            };
            let call = ToolCall {
                name: name.clone(),
                arguments: "{}".to_owned(),
            };
            match deny(&call) {
                Some(reason) => {
                    removed.push((name, reason));
                    false
                }
                None => true,
            }
        });
        if tools.is_empty()
            && let Some(obj) = body.as_object_mut()
        {
            obj.remove("tools");
            // A tool_choice naming a removed tool would now be invalid.
            obj.remove("tool_choice");
        }
    }
    removed
}

/// The text the agent sees in place of a blocked call.
pub fn refusal_text(name: &str, reason: &str) -> String {
    format!(
        "[sentinel] The call to tool `{name}` was blocked and not executed: {reason}. \
         Choose a different approach."
    )
}

/// One denied call in a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// The call.
    pub call: ToolCall,
    /// Why.
    pub reason: String,
}

/// Judges every tool call in a non-streaming response body and replaces
/// the denied ones with a refusal the agent can act on. Returns the denied
/// calls; the body is changed only if there are any.
pub fn rewrite_response(
    api: Api,
    body: &mut Value,
    mut deny: impl FnMut(&ToolCall) -> Option<String>,
) -> Vec<Denied> {
    let mut denied = Vec::new();
    match api {
        Api::AnthropicMessages => {
            let mut remaining = 0;
            if let Some(content) = body.get_mut("content").and_then(Value::as_array_mut) {
                for block in content.iter_mut() {
                    if block["type"] != "tool_use" {
                        continue;
                    }
                    let call = ToolCall {
                        name: str_field(block, "name").unwrap_or_default(),
                        arguments: args_string(block.get("input")),
                    };
                    match deny(&call) {
                        Some(reason) => {
                            *block = json!({"type": "text", "text": refusal_text(&call.name, &reason)});
                            denied.push(Denied { call, reason });
                        }
                        None => remaining += 1,
                    }
                }
            }
            if !denied.is_empty() && remaining == 0 && body["stop_reason"] == "tool_use" {
                body["stop_reason"] = json!("end_turn");
            }
        }
        Api::OpenAiChat => {
            for choice in body
                .get_mut("choices")
                .and_then(Value::as_array_mut)
                .into_iter()
                .flatten()
            {
                let Some(message) = choice.get_mut("message").and_then(Value::as_object_mut) else {
                    continue;
                };
                let mut refusals = Vec::new();
                if let Some(calls) = message.get_mut("tool_calls").and_then(Value::as_array_mut) {
                    calls.retain(|tc| {
                        let call = ToolCall {
                            name: str_field(&tc["function"], "name").unwrap_or_default(),
                            arguments: args_string(tc["function"].get("arguments")),
                        };
                        match deny(&call) {
                            Some(reason) => {
                                refusals.push(refusal_text(&call.name, &reason));
                                denied.push(Denied { call, reason });
                                false
                            }
                            None => true,
                        }
                    });
                }
                if refusals.is_empty() {
                    continue;
                }
                let none_left = message
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty);
                if none_left {
                    message.remove("tool_calls");
                }
                append_text(message, &refusals.join("\n"));
                if none_left && choice["finish_reason"] == "tool_calls" {
                    choice["finish_reason"] = json!("stop");
                }
            }
        }
        Api::OpenAiResponses => {
            if let Some(output) = body.get_mut("output").and_then(Value::as_array_mut) {
                for item in output.iter_mut() {
                    if item["type"] != "function_call" {
                        continue;
                    }
                    let call = ToolCall {
                        name: str_field(item, "name").unwrap_or_default(),
                        arguments: args_string(item.get("arguments")),
                    };
                    if let Some(reason) = deny(&call) {
                        *item = json!({
                            "type": "message",
                            "role": "assistant",
                            "status": "completed",
                            "content": [{
                                "type": "output_text",
                                "text": refusal_text(&call.name, &reason),
                                "annotations": [],
                            }],
                        });
                        denied.push(Denied { call, reason });
                    }
                }
            }
        }
    }
    denied
}

fn append_text(message: &mut Map<String, Value>, text: &str) {
    let content = match message.get("content").and_then(Value::as_str) {
        Some(existing) if !existing.is_empty() => format!("{existing}\n{text}"),
        _ => text.to_owned(),
    };
    message.insert("content".to_owned(), Value::String(content));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny_bash(call: &ToolCall) -> Option<String> {
        (call.name == "bash").then(|| "no shells".to_owned())
    }

    #[test]
    fn detects_apis() {
        assert_eq!(Api::detect("POST", "/v1/messages"), Some(Api::AnthropicMessages));
        assert_eq!(Api::detect("POST", "/openai/v1/chat/completions"), Some(Api::OpenAiChat));
        assert_eq!(Api::detect("POST", "/v1/responses"), Some(Api::OpenAiResponses));
        assert_eq!(Api::detect("GET", "/v1/messages"), None);
        assert_eq!(Api::detect("POST", "/v1/models"), None);
    }

    #[test]
    fn finds_history_calls() {
        let anthropic = json!({"messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "ok"},
                {"type": "tool_use", "id": "t1", "name": "bash", "input": {"cmd": "ls"}},
            ]},
        ]});
        assert_eq!(
            history_calls(Api::AnthropicMessages, &anthropic),
            vec![ToolCall { name: "bash".into(), arguments: r#"{"cmd":"ls"}"#.into() }]
        );
        let chat = json!({"messages": [{"role": "assistant", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "bash", "arguments": "{\"cmd\":\"ls\"}"}},
        ]}]});
        assert_eq!(history_calls(Api::OpenAiChat, &chat)[0].arguments, r#"{"cmd":"ls"}"#);
        let responses = json!({"input": [
            {"type": "function_call", "name": "bash", "arguments": "{}", "call_id": "c"},
        ]});
        assert_eq!(history_calls(Api::OpenAiResponses, &responses)[0].name, "bash");
    }

    #[test]
    fn strips_declared_tools() {
        let mut body = json!({"tools": [{"name": "bash"}, {"name": "get_weather"}]});
        let removed = strip_declared_tools(Api::AnthropicMessages, &mut body, deny_bash);
        assert_eq!(removed.len(), 1);
        assert_eq!(body["tools"], json!([{"name": "get_weather"}]));

        let mut body = json!({
            "tools": [{"type": "function", "function": {"name": "bash"}}],
            "tool_choice": {"type": "function", "function": {"name": "bash"}},
        });
        strip_declared_tools(Api::OpenAiChat, &mut body, deny_bash);
        assert_eq!(body, json!({}));
    }

    #[test]
    fn rewrites_anthropic_response() {
        let mut body = json!({
            "content": [
                {"type": "text", "text": "Let me run that."},
                {"type": "tool_use", "id": "t1", "name": "bash", "input": {"cmd": "rm -rf /"}},
            ],
            "stop_reason": "tool_use",
        });
        let denied = rewrite_response(Api::AnthropicMessages, &mut body, deny_bash);
        assert_eq!(denied.len(), 1);
        assert_eq!(body["content"][1]["type"], "text");
        assert!(body["content"][1]["text"].as_str().unwrap().contains("blocked"));
        assert_eq!(body["stop_reason"], "end_turn");
    }

    #[test]
    fn rewrites_openai_responses() {
        let mut chat = json!({"choices": [{
            "message": {"role": "assistant", "content": null, "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "bash", "arguments": "{}"}},
            ]},
            "finish_reason": "tool_calls",
        }]});
        assert_eq!(rewrite_response(Api::OpenAiChat, &mut chat, deny_bash).len(), 1);
        let choice = &chat["choices"][0];
        assert!(choice["message"].get("tool_calls").is_none());
        assert!(choice["message"]["content"].as_str().unwrap().contains("bash"));
        assert_eq!(choice["finish_reason"], "stop");

        let mut resp = json!({"output": [
            {"type": "function_call", "name": "bash", "arguments": "{}", "call_id": "c"},
        ]});
        assert_eq!(rewrite_response(Api::OpenAiResponses, &mut resp, deny_bash).len(), 1);
        assert_eq!(resp["output"][0]["type"], "message");
    }

    #[test]
    fn allowed_calls_leave_the_body_alone() {
        let original = json!({"content": [
            {"type": "tool_use", "id": "t1", "name": "get_weather", "input": {}},
        ], "stop_reason": "tool_use"});
        let mut body = original.clone();
        assert!(rewrite_response(Api::AnthropicMessages, &mut body, deny_bash).is_empty());
        assert_eq!(body, original);
    }
}
