# Quickstart

Clients behind roxy, with three controls on every model call:

- an **auth gate**: a WASM addon that checks the client's credential with a
  central auth service and tags the flow with the user it belongs to;
- a **token quota**: a WASM addon that asks a quota service whether that
  user's token bucket holds anything, and reports the tokens each response used;
- the **sentinel**: an [inspect_sentinel](https://github.com/meridianlabs-ai/inspect_sentinel)
  sidecar that blocks tool calls matching a denylist.

roxy runs in node mode: it enrols with a minimal **control plane** and leases
its policy, the model's API key and its flow-shipping settings from there,
and ships its flow log back. The model is a scripted stand-in and the traffic
is generated, so nothing here needs an API key or a route out: start it and
watch. The walkthrough is the
[quickstart](https://roxy-proxy.github.io/roxy-proxy/quickstart) on the docs site.

```sh
docker compose up --build --attach traffic   # alice, bob and mallory calling on their own cadences
open http://127.0.0.1:8090                   # the quota board
open http://127.0.0.1:7575                   # Inspect View: the sentinel's verdicts
docker compose run --rm client --user bob    # a call of your own, from another terminal
```

Ctrl-C stops the stack; `docker compose down -v` removes it. To run roxy
from `roxy.yaml` directly, with no control plane:

```sh
docker compose -f compose.yaml -f compose.standalone.yaml up --build --attach traffic
```

| file | what it is |
|---|---|
| [`compose.yaml`](compose.yaml) | roxy in node mode with the addons, the control plane, the three mock services, the sentinel, Inspect View, the traffic and the one-off client |
| [`compose.standalone.yaml`](compose.standalone.yaml) | an override that runs roxy from `roxy.yaml` instead, without the control plane |
| [`roxy.yaml`](roxy.yaml) | the policy: the three addons in order, and a rule that lets the client reach the model and puts the API key on the request. The control plane serves it as the lease |
| [`controlplane/`](controlplane/) | the control plane: enrolment, mTLS, the lease, revocation (`revoked` in its data dir) and flow uploads, in one Python file |
| [`addons/auth-gate`](addons/auth-gate/src/lib.rs) | the auth gate: `x-roxy-auth` to the auth service, verdict cached in the layer's state, `user:<name>` tag |
| [`addons/token-quota`](addons/token-quota/src/lib.rs) | the quota: a check before the call, a report of the usage the response carried after it |
| [`addons/Dockerfile`](addons/Dockerfile) | builds both addons for `wasm32-wasip2` and puts them in roxy's image |
| [`mocks/fake_model.py`](mocks/fake_model.py) | the model: the responses in [`responses.json`](mocks/responses.json), in order, streamed or whole, with Anthropic-shaped usage |
| [`mocks/auth_service.py`](mocks/auth_service.py) | the auth service: which credential is whose |
| [`mocks/quota_board.py`](mocks/quota_board.py) | the quota service: a token bucket per user, with a live page and the last five minutes of levels |
| [`mocks/traffic.py`](mocks/traffic.py) | the traffic: a call every few seconds for each user in `TRAFFIC_SCHEDULE` |
| [`mocks/chat.py`](mocks/chat.py) | the client the traffic uses: the Anthropic SDK through roxy, as a named user |
| [`sentinel/`](sentinel/) | the sentinel sidecar, a service layer; `SENTINEL_DENY` sets its regex |
| [`smoke.sh`](smoke.sh) | runs the stack, waits for each control to fire in the traffic's log, and checks the lease running down and recovering |

The sentinel sidecar's and the control plane's own tests run with `pytest`
in `sentinel/` and `controlplane/`; the addons' with `cargo test` in `addons/`.
