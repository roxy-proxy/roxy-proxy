# Testing a policy

`roxy check` validates a config and prints diagnostics. `roxy rule test`
shows what the policy does with a request you describe, without sending
any traffic.

```sh
roxy check --config roxy.yaml        # exits 1 with diagnostics
```

```sh
roxy rule test --config roxy.yaml GET https://api.github.com/repos/a/b
roxy rule test --config roxy.yaml --metric github_writes=30 POST https://api.github.com/repos/a/b/issues
```

`roxy rule test` evaluates a synthetic request with no network I/O and
prints the matching rules, the effects and the decision. It exits 0 on
allow and 3 on deny. Metrics you do not pass are 0, and
`--metric id=unavailable` exercises the fail-closed path. `--client-ip`,
`--user`, `--header` and `--body` set the request; `--state key=value`
seeds the state store and `--tag name` sets a tag before the rules run.
`--body-bytes` and `--response-body-bytes` run the watching rules that read
those counts; `--response-status` runs the rules that read the response
head (`--response-header` adds headers to it but on its own runs nothing).
`--ws-text`, `--ws-opcode`, `--ws-size` and `--ws-direction` describe one
WebSocket message and run the rules that read `ws.*`. The request arrives on the config's first listener, which
sets `listener.name` and `listener.mode`. An IP-literal URL also shows an
address-floor hit. See `roxy rule test --help`.
