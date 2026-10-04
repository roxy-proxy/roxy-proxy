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
`--metric id=unavailable` exercises the fail-closed path. Flags set the
client, headers and body, and `--body-bytes`, `--response-status`,
`--response-header` and `--response-body-bytes` run the watching rules
that read them. `--ws-text`, `--ws-opcode`, `--ws-size` and
`--ws-direction` describe one WebSocket message and run the rules that
read `ws.*`. An IP-literal URL also shows an address-floor hit. See
`roxy rule test --help`.
