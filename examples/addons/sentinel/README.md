# sentinel: an example roxy addon

A small inspect-sentinel (DESIGN.md §11.7). It blocks LLM tool calls by
policy in the traffic of an agent behind roxy. It is deliberately basic and
makes **no model calls**. [`src/judge.rs`](src/judge.rs) shows where one
would go.

## What it does

It recognises three APIs by request path (`POST`):

- Anthropic Messages (`/v1/messages`)
- OpenAI Chat Completions (`/v1/chat/completions`)
- OpenAI Responses (`/v1/responses`)

Everything else passes through untouched.

**On the request:**

- Tools the policy denies are removed from `tools`, so the model never sees
  them. If that empties `tools`, `tool_choice` is removed as well.
- A conversation whose history contains a denied call (the agent ran one
  anyway) is refused with `403`, in the API's own error shape.
- `accept-encoding: identity` is set so the response can be inspected.
- A compressed request body (`415`), or one too large to inspect (`413`),
  is refused.
- OpenAI requests with `"stream": true` are refused (`400`): only Anthropic
  streams are inspected.

**On the response:**

- A denied tool call is replaced by a text refusal the agent can act on
  (§11.7 `reject`).
  - Anthropic: the `tool_use` block becomes a `text` block, and
    `stop_reason` becomes `end_turn` if no call is left.
  - OpenAI Chat: the call is removed from `tool_calls`, the refusal is
    appended to `content`, and `finish_reason` becomes `stop`.
  - OpenAI Responses: the `function_call` item becomes an assistant
    `message`.
- In a streamed Anthropic response (`text/event-stream`), text streams
  through as it arrives, while each `tool_use` block is withheld until it
  is complete. It is then judged, and either released byte for byte or
  replaced by a text block. A stream that ends in the middle of a
  `tool_use` block drops it.
- A response with nothing denied passes through byte for byte.
- A response that cannot be inspected (compressed, too large, or an OpenAI
  stream) is answered with `502`, failing closed.

**Every denial** is recorded:

```text
flow.record("sentinel_decision", {api, direction, tool, arguments, verdict, reason}, audit: true)
```

With `terminate_after: N`, the N-th denial for a principal (proxy-auth user,
else client IP) quarantines it with `flow.terminate(principal)` for
`terminate_ttl_secs`, and records `sentinel_terminate`.

## Policy

The layer's `config:`, as JSON:

| key | default | meaning |
|---|---|---|
| `deny_tools` | `[]` | regexes; a call whose tool name matches is denied |
| `deny_args` | `[]` | regexes; a call whose JSON-serialised arguments match is denied |
| `terminate_after` | none | quarantine the principal after this many denials |
| `terminate_ttl_secs` | `3600` | how long the violation count and the quarantine last |
| `max_body_bytes` | 8 MiB | largest body read for inspection |

Patterns use [regex-lite](https://docs.rs/regex-lite) syntax (ASCII
classes; no Unicode tables).

## Configuration

```yaml
addons:
  - name: sentinel
    kind: wasm
    path: /etc/roxy/addons/sentinel.wasm
    mode: enforce                        # observe: watch and record only
    capabilities: [record, state, terminate]
    limits:
      max_buffered_body_bytes: 8mb       # requests resend the whole conversation
    config:
      deny_tools: ["^bash$", "^computer$"]
      deny_args: ['rm\s+-rf', 'curl\s+[^|]*\|\s*sh']
      terminate_after: 3
    # Only needed once judge() calls a model; see src/judge.rs.
    # endpoints:
    #   monitor-model:
    #     url: https://api.anthropic.com/v1/messages
    #     headers: { x-api-key: "${secret:monitor_key}" }
    #     timeout: 10s
```

The rules still judge every request the sentinel lets through, so keep
the API hosts allowed there as usual.

## Turning it into a real sentinel

[`src/judge.rs`](src/judge.rs) holds the one decision function. Its doc
comment and the commented-out `judge_with_model` show how to ask a monitor
model through a **named endpoint**, and explain why that is safe:

- roxy attaches the credentials, so the layer never sees them;
- the layer names an endpoint and cannot choose a URL;
- endpoint calls bypass the layer stack, so the monitor's own call cannot
  recurse into the sentinel.

Run an uncalibrated scorer in `mode: observe` first.

## Building

```sh
rustup target add wasm32-wasip2
../build.sh             # builds every example and copies sentinel.wasm here
cargo test              # unit tests of the parsing and policy, natively
```

`sentinel.wasm` is checked in. roxy's tests
(`crates/roxy-wasm/tests/sentinel.rs`) run it under the real host, so
rebuild and commit it after changing the source. CI rebuilds it and runs
those tests against the fresh build.
