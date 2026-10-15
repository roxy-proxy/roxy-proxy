# Human approval of every tool call

Claude Code behind roxy, with a person in the loop: every tool call the
model returns is held at the proxy and shown on a page in the browser, and
nothing reaches the agent until someone clicks **Approve** or **Deny**.
There is no denylist and nothing to configure; the person is the policy.

Under the hood it is the [quickstart](../quickstart/sentinel/)'s
[inspect_sentinel](https://github.com/meridianlabs-ai/inspect_sentinel)
sidecar with inspect_sentinel's own `human()` protocol at the root, and a
small review queue as its `ask_human`. The stream handling and the
`roxy.layer.v6` protocol are imported from there unchanged.

| file | what it is |
|---|---|
| [`approval.py`](approval.py) | the layer: the quickstart `Sidecar` with `human(stages=["tool_call"], choices=["approve", "reject"])` and the review queue as its host |
| [`review.py`](review.py) | the queue (`ask_human` parks the step on a future) and the three-route page server: `GET /`, `GET /pending`, `POST /pending/{id}` |
| [`review.html`](review.html) | the page: one card per waiting call, an optional reason, Approve and Deny |
| [`roxy.yaml`](roxy.yaml) | roxy's policy: the layer on `POST api.anthropic.com/v1/messages`, a rule that lets that host through, everything else denied |
| [`compose.yaml`](compose.yaml) | the same two processes as containers: roxy from [`roxy.compose.yaml`](roxy.compose.yaml) (the policy with container addresses), the layer built from [`Dockerfile`](Dockerfile) |
| [`tests/`](tests/) | the hold, the two answers, the pings, a whole response, an exchange that goes away, and the page's refusals |

## Running it

Three terminals, all from the repository root. Python 3.12 or later and a
Rust toolchain (or a `roxy` binary) are needed.

**1. The review layer.** It listens for roxy on `127.0.0.1:9000` and serves
the page on `127.0.0.1:8585`:

```sh
cd examples/human-approval
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python approval.py
```

**2. roxy.** The proxy is on `127.0.0.1:8080`; its CA is generated into
`examples/human-approval/ca/` on the first run (gitignored) and served on
`127.0.0.1:8081`:

```sh
cargo run --release --bin roxy -- run --config examples/human-approval/roxy.yaml
```

**3. Claude Code**, pointed at roxy and trusting its CA:

```sh
curl -fsS -o /tmp/roxy-ca.pem http://127.0.0.1:8081/roxy-ca.pem
export HTTPS_PROXY=http://127.0.0.1:8080 NODE_EXTRA_CA_CERTS=/tmp/roxy-ca.pem
claude
```

Open <http://127.0.0.1:8585> and ask Claude Code to do something that takes
a tool: read a file, run a command. Its API key goes through roxy as it is;
roxy only relays `api.anthropic.com`. Anything else Claude Code reaches for
(telemetry, update checks) is denied by the rules and shows up in roxy's
flow log on stdout.

## With Docker

One command, from this directory:

```sh
cd examples/human-approval
docker compose up --build -d
```

That starts roxy (`ghcr.io/roxy-proxy/roxy:0.3`) with the proxy on
`127.0.0.1:8080` and its CA on `127.0.0.1:8081`, and the review layer with
its page on `127.0.0.1:8585`. Then, in a shell of your own, point Claude
Code at it:

```sh
curl -fsS -o /tmp/roxy-ca.pem http://127.0.0.1:8081/roxy-ca.pem
export HTTPS_PROXY=http://127.0.0.1:8080 NODE_EXTRA_CA_CERTS=/tmp/roxy-ca.pem
claude
```

If something Claude Code runs must reach a host directly (an API key
helper, say, or other tooling of yours), list it in `NO_PROXY` so it is not
sent through roxy and denied.

Open <http://127.0.0.1:8585> and carry on as above. roxy's flow log is
`docker compose logs roxy`.

The CA lives in the `roxy-ca` volume, so it survives `docker compose
restart` and `down`; `docker compose down -v` removes it, and Claude Code
must then trust the new one. The Inspect log is in the `review-logs`
volume, mounted at `/logs` in the `review` container:
`docker compose cp review:/logs ./logs` copies it out for
`inspect view --log-dir logs`.

## What the person sees

Each tool call the model returns is a card: the tool's name, what the model
said alongside the call, its arguments as JSON, how long it has been
waiting, a box for a reason, and the two buttons. A response with several
tool calls in it is several cards, asked one after the other: the second
appears once the first is approved, and a denial of any one of them denies
the response. The page polls once a second and the tab title counts what is
waiting.

- **Approve**: the response goes to the agent exactly as the model sent it,
  and the agent runs the tool.
- **Deny**: the agent gets an assistant message in the response's place: the
  model's text, no tool calls, and
  `A person reviewing this session denied the <tool> tool call: <reason>`.
  Its stop reason is `end_turn`, so the agent's turn ends and the person at
  the Claude Code prompt gets to say what to do instead.

While a call waits, Claude Code sees a response that has started (its
`message_start` event) and then a `ping` every ten seconds, which is what
the API itself sends while a model thinks, so its spinner keeps spinning.

Everything asked and answered is also written as an Inspect eval log
(`--log-dir`, default `$TMPDIR/roxy-human-approval`) for `inspect view`.

## What bounds a hold

Nothing in the layer itself: a card waits until it is answered or its
exchange goes away. The clocks that can end it first are:

| clock | where | when it fires |
|---|---|---|
| the agent's own API timeout | Claude Code | the whole call takes too long, pings or not. Claude Code then retries the call: the old card disappears (its exchange was reset) and the tool call comes back as a new one |
| `addons[].limits.first_byte_timeout` | `roxy.yaml`, 30 m | only for a response the agent asked for whole (no `stream: true`): nothing has been sent, so this is how long the person has. A streamed response has started, so this is met at once |
| `limits.response_body_idle_timeout` | `roxy.yaml`, 30 m | a streamed hold with no bytes for this long. The pings reset it every ten seconds, so it fires only if the layer stops pinging |

Restarting `approval.py` while calls are waiting fails them closed: roxy
denies each in-flight exchange (`503`, `layer:human-approval`, or a cut
stream if its head had gone), the queue starts empty, and roxy dials the
new process for the next call. Claude Code retries, so the same tool calls
come back as new cards. With the layer not running at all, every model
call is denied the same way: nothing gets through unreviewed.

## Tests

```sh
cd examples/human-approval
pip install -r requirements.txt -r requirements-test.txt
pytest
```

The tests drive the layer with the quickstart's fake roxy and the page with
aiohttp's test client, so no proxy, model or browser is involved.
