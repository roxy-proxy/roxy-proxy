# Quickstart

Claude Code behind roxy and an inspect_sentinel sidecar that blocks tool
calls matching a denylist. The walkthrough is the
[quickstart](https://roxy-proxy.github.io/roxy-proxy/quickstart) on the docs
site.

```sh
docker compose up -d --wait
curl -fsS http://127.0.0.1:3130/roxy-ca.pem -o roxy-ca.pem
HTTPS_PROXY=http://127.0.0.1:3128 NODE_EXTRA_CA_CERTS=$PWD/roxy-ca.pem \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 claude
```

| file | what it is |
|---|---|
| [`compose.yaml`](compose.yaml) | roxy and the sentinel sidecar |
| [`roxy.yaml`](roxy.yaml) | the policy: Anthropic's API and sign-in hosts, every exchange through the sentinel |
| [`test.sh`](test.sh), [`compose.test.yaml`](compose.test.yaml) | an end-to-end check with a fake model, run by CI |
