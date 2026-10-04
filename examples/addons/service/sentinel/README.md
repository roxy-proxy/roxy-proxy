# inspect_sentinel as a roxy service layer

[inspect_sentinel](https://github.com/meridianlabs-ai/inspect_sentinel)
monitors and control protocols watch an agent's tool calls. Run in roxy's
network path, they judge every model API response before the agent sees
it, and the agent cannot route around them: its only way out is roxy.

`sidecar.py` is the host side of inspect_sentinel for a proxy, the
"sidecar" deployment its design describes:

- For an Anthropic Messages (`/v1/messages`) or OpenAI Chat Completions
  (`/chat/completions`) call, it forwards the request, reads the response
  (rebuilding a streamed Anthropic response from its events), converts
  both with inspect_ai's wire-format converters, and runs the sentinel on
  each tool call as a `BeforeToolCall` step. Other traffic streams through
  untouched.
- Decisions: `continue` passes the response on; `modify` rewrites the tool
  call's arguments (JSON responses); `reject`, `terminate` and an
  unresolved `escalate` refuse the response. By default the agent gets a
  `403` carrying the decision's message. With `SENTINEL_ON_REJECT=explain`,
  an Anthropic response (plain or streamed) is replaced by an assistant
  message that keeps the model's text, drops the tool calls and says what
  was blocked, so an agent such as Claude Code ends its turn normally
  instead of reporting an API error.
- It implements `Host` (`generate` calls `SENTINEL_MONITOR_MODEL` directly,
  never through roxy, so a monitor cannot recurse through itself), a
  `Recorder` that prints each report as a JSON line tagged with roxy's flow
  id, and a store per conversation, keyed by a fingerprint of the
  conversation's stable head so the agent cannot rotate it.

[`policies.py`](policies.py) has three sentinels that need no model:
`no_network` (a rule rejecting tool calls that use `curl`, `wget`, ...),
`deny_regex` (a rule rejecting tool calls whose name or arguments match the
regex in `SENTINEL_DENY`) and `watch` (a monitor recorded with
`observe_only`). Any inspect_sentinel
monitor or protocol works: point `SENTINEL` at it.

## Try it

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt
cargo build -p roxy
PYTHON=.venv/bin/python ./demo.sh
```

[`demo.sh`](demo.sh) runs a fake model API ([`fake_anthropic.py`](fake_anthropic.py)),
roxy with the sidecar as a service layer, and asks for a benign and a
harmful tool call, plain and streamed, first with the default `403` and
then with `SENTINEL_ON_REJECT=explain`:

```
benign tool call             200  {"id": "msg_1", "type": "message", ...
curl tool call               403  `curl` needs the network, which is not allowed here.
benign, streamed             200  event: message_start ...
curl tool call, streamed     403  `curl` needs the network, which is not allowed here.
```

## Configuration

| variable | default | |
|---|---|---|
| `SENTINEL` | `policies:no_network` | `module:attribute` of the sentinel (called if it is a factory) |
| `SENTINEL_MONITOR_MODEL` | none | the model `context.host.generate` uses, e.g. `anthropic/claude-haiku-4-5` |
| `SENTINEL_LISTEN` | `127.0.0.1:9000` | where to listen |
| `SENTINEL_TASK` | `roxy` | `context.task` |
| `SENTINEL_ON_REJECT` | `deny` | `deny`: a refused response is a `403`; `explain`: an Anthropic response becomes an assistant message saying what was blocked |
| `SENTINEL_DENY` | curl, wget, nc, ssh, scp, rsync, `rm -rf` | the regex `deny_regex` searches for in `<tool> <arguments as JSON>` |

Start a new monitor in `mode: observe` in roxy (it sees everything and
cannot block), and move it to `enforce` once its threshold is calibrated.

## What a proxy cannot do (yet)

From inspect_sentinel's deployment design, and true here:

- `AfterToolCall` is lossy at a proxy (a tool result shows up only in the
  next request); this sidecar does not project it.
- `reject` is an error the agent's SDK raises, or with `explain` the end
  of the agent's turn, not the append-and-regenerate replay an eval does.
- A streamed response is held until judged, which costs time to first
  token. With `explain`, its head and `message_start` go to the agent at
  once and pings follow while it is judged, so the agent's first-byte and
  idle deadlines are met; its content still arrives in one burst. OpenAI streaming is refused rather than passed unjudged.
- `terminate` cannot end the agent from here; it refuses the response.

A compiled build of the same sentinels, running inside roxy as a WASM
layer, is the `inspect-sentinel-wasm` slot in
[`../../README.md`](../../README.md), for when inspect_sentinel has an
embedded build.
