# Testing a policy

`roxy check` validates a config. `roxy rule test` shows what the policy
does with a request you describe, without sending any traffic.

```sh
roxy check --config roxy.yaml        # exits 1 with diagnostics
roxy rule test --config roxy.yaml GET https://api.github.com/repos/a/b
roxy rule test --config roxy.yaml --metric github_writes=30 POST https://api.github.com/repos/a/b/issues
```

`roxy rule test` prints the matching rules, their effects and the
decision. It exits 0 on allow and 3 on deny. The request arrives on the
config's first listener.

The rules see the request as `roxy run` would: the URL is normalised
(`https://H.example./a/%2e/b/../c` has `host == "h.example"` and
`path == "/a/c"`), and a request roxy would refuse as malformed exits 1
with the same reason.

## Describing the request

| flag | sets |
|---|---|
| `--client-ip`, `--header`, `--body` | the request |
| `--chunked` | a body of unknown length |
| `--metric id=value` | a metric's value; unset metrics are 0, and `unavailable` tests the fail-closed path |
| `--state key=value` | an entry in the state store |
| `--tag name` | a tag, set before the rules run |
| `--body-bytes`, `--response-body-bytes` | byte counts, for rules that read them |
| `--response-status`, `--response-header` | the response head, for rules that read it |
| `--ws-text`, `--ws-opcode`, `--ws-size`, `--ws-direction` | one WebSocket message |

`roxy rule test --help` lists every flag.
