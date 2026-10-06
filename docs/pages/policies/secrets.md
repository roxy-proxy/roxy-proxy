# Secrets

`secrets:` maps names to where each value comes from: an environment
variable, a file, or the control-plane lease (`{ lease: true }`), which
supplies the value at runtime. `${secret:name}` in a head rule's
`set_header` value (or an addon endpoint's `headers`) injects the value, so
the client only ever holds a placeholder; a secret reference anywhere else
in a rule is a compile error. `env` and `file` secrets are resolved when
roxy starts and on reload, and one that is missing or empty is a fatal start
or reload error. At evaluation time a missing secret fails the flow closed
(`_fail_closed`, reason `secret_missing`), and so does one that is not a
valid header value (`secret_invalid`). Every injected value is redacted from
the flow log and capture heads. `roxy check` and `roxy rule test` do not
resolve secrets.

```yaml
secrets:
  openai: { env: OPENAI_API_KEY }
  gh:     { file: /run/secrets/github_token }   # one trailing newline (`\n` or `\r\n`) stripped; warns if group or world can read it
  lease:  { lease: true }                       # supplied by the control-plane lease

rules:
  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }
      - allow
```

The client can send any placeholder in `authorization`; `set_header`
replaces it before the request is forwarded.

## Lease secrets

`name: { lease: true }` declares a secret the config does not resolve: the
control plane hands the value over in memory with the lease, together with
the rest of the map. `roxy check` accepts the document, since it never
resolves secrets, but standalone `roxy run --config` has no lease and
refuses to start, naming the secret. A secret has exactly one of `env`,
`file` or `lease: true`; `{}`, `null`, a bare word and `lease: false` are
parse errors.

Secret values live in a store beside the compiled policy, not inside it.
Replacing the map swaps the store and rebuilds the redactor without
recompiling rules, rebuilding addons or flushing upstream pools, and
without a reload event. A request evaluated after the swap injects the new
value; an exchange already under way keeps the one it injected, and the
redactor scrubs both until the next swap. A name the policy references but
the map lacks fails the flow closed (`secret_missing`). Values never appear
in the config file, on disk or in logs. A config reload resolves `env` and
`file` sources into the same store and swaps the policy as usual.
