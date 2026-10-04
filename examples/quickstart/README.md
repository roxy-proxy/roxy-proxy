# Quickstart

Claude Code behind roxy and an
[inspect_sentinel](https://github.com/meridianlabs-ai/inspect_sentinel)
sidecar that blocks tool calls matching a denylist, with Inspect View
showing each conversation and the sentinel's verdicts. The walkthrough is
the [quickstart](https://roxy-proxy.github.io/roxy-proxy/quickstart) on the
docs site.

```sh
docker compose up -d --wait
curl -fsS http://127.0.0.1:3130/roxy-ca.pem -o roxy-ca.pem
HTTPS_PROXY=http://127.0.0.1:3128 NODE_EXTRA_CA_CERTS=$PWD/roxy-ca.pem \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 claude
open http://127.0.0.1:7575    # Inspect View
```

| file | what it is |
|---|---|
| [`compose.yaml`](compose.yaml) | roxy, the sentinel sidecar and Inspect View |
| [`roxy.yaml`](roxy.yaml) | the policy: Anthropic's API and sign-in hosts, every exchange through the sentinel |
| [`sentinel/sidecar.py`](sentinel/sidecar.py) | the sidecar: judges each tool call in a model response, and replaces a refused response with an explanation |
| [`sentinel/policies.py`](sentinel/policies.py) | `deny_regex`, the sentinel it runs (`SENTINEL_DENY` sets the regex) |
| [`sentinel/inspect_log.py`](sentinel/inspect_log.py) | writes conversations and verdicts as an Inspect eval log |
| [`sentinel/roxy_layer.py`](sentinel/roxy_layer.py) | the service side of roxy's service-layer protocol, for asyncio |
