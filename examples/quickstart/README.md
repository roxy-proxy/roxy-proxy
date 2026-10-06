# Quickstart

A chat client behind roxy, with three controls on every model call:

- an **auth gate**: a WASM addon that checks the client's credential with a
  central auth service and tags the flow with the user it belongs to;
- a **token quota**: a WASM addon that asks a quota service whether that
  user may still spend, and reports the tokens each response used;
- the **sentinel**: an [inspect_sentinel](https://github.com/meridianlabs-ai/inspect_sentinel)
  sidecar that blocks tool calls matching a denylist.

The model is a scripted stand-in, so nothing here needs an API key or a
route out. The walkthrough is the
[quickstart](https://roxy-proxy.github.io/roxy-proxy/quickstart) on the docs site.

```sh
docker compose up -d --build --wait
docker compose run --rm client --user alice --repeat 6   # the sixth call gets a 429
docker compose run --rm client --user bob                # bob has his own quota
docker compose run --rm client --user mallory --secret wrong   # 401
open http://127.0.0.1:8090    # the quota board
open http://127.0.0.1:7575    # Inspect View: the sentinel's verdicts
```

| file | what it is |
|---|---|
| [`compose.yaml`](compose.yaml) | roxy with the addons, the three mock services, the sentinel, Inspect View and the client |
| [`roxy.yaml`](roxy.yaml) | the policy: the three addons in order, and a rule that lets the client reach the model and puts the API key on the request |
| [`addons/auth-gate`](addons/auth-gate/src/lib.rs) | the auth gate: `x-roxy-auth` to the auth service, verdict cached in the layer's state, `user:<name>` tag |
| [`addons/token-quota`](addons/token-quota/src/lib.rs) | the quota: a check before the call, a report of the usage the response carried after it |
| [`addons/Dockerfile`](addons/Dockerfile) | builds both addons for `wasm32-wasip2` and puts them in roxy's image |
| [`mocks/fake_model.py`](mocks/fake_model.py) | the model: the responses in [`responses.json`](mocks/responses.json), in order, streamed or whole, with Anthropic-shaped usage |
| [`mocks/auth_service.py`](mocks/auth_service.py) | the auth service: which credential is whose |
| [`mocks/quota_board.py`](mocks/quota_board.py) | the quota service and its live page |
| [`mocks/chat.py`](mocks/chat.py) | the client: the Anthropic SDK through roxy, as a named user |
| [`sentinel/`](sentinel/) | the sentinel sidecar, a service layer; `SENTINEL_DENY` sets its regex |
| [`smoke.sh`](smoke.sh) | runs the stack and checks each control fires |

The sentinel sidecar's own tests run with `pytest` in `sentinel/`; the
addons' with `cargo test` in `addons/`.
