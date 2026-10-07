# Testing a policy

`roxy check` validates a config and prints diagnostics
([check and reload](/guides/operations#reload)). `roxy rule test`
shows what the policy does with a request you describe, without sending
any traffic.

```sh
roxy check --config roxy.yaml        # exits 1 with diagnostics
roxy rule test --config roxy.yaml GET https://api.github.com/repos/a/b
roxy rule test --config roxy.yaml --metric github_writes=30 POST https://api.github.com/repos/a/b/issues
```

`roxy rule test` evaluates a synthetic request with no network I/O and
prints the matching rules, the effects and the decision. It exits 0 on
allow and 3 on deny. The request arrives on the config's first listener,
which sets `listener.name`. `roxy rule test --help` lists every flag.

## What the rules see

The canonical request, as in `roxy run`:

- The URL is parsed and normalised by the proxy's own parser
  (`https://H.example./a/%2e/b/../c` is `host == "h.example"` and
  `path == "/a/c"`).
- Hop-by-hop fields such as `connection` are removed, and
  `header["host"]`, `header["content-length"]` and `header["upgrade"]` come
  from the parsed request rather than from `--header`.
- A request the proxy would refuse (a non-ASCII host, a path that climbs
  above the root, a `Host` that does not match the URL) exits 1 with the
  same reason code.
- An IP-literal URL also shows an address-floor hit.

## Describing the request

| flag | sets |
|---|---|
| `--client-ip`, `--header`, `--body` | the request |
| `--chunked` | `body.size` and `header["content-length"]` to `null`, as for a chunked body that has not been buffered |
| `--metric id=value` | a metric's value; unset metrics are 0, `--metric id=unavailable` exercises the fail-closed path, and an id the config does not define gets a warning |
| `--state key=value` | an entry in the state store |
| `--tag name` | a tag, before the rules run |
| `--body-bytes`, `--response-body-bytes` | the byte counts, running the watching rules that read them |
| `--response-status`, `--response-header` | the response head, running the rules that read it (`--response-header` on its own runs nothing) |
| `--ws-text`, `--ws-opcode`, `--ws-size`, `--ws-direction` | one WebSocket message, running the rules that read `ws.*` |
