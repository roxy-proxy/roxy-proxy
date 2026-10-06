# Secrets

`secrets:` maps names to an environment variable or a file. `${secret:name}`
in a head rule's `set_header` value (or an addon endpoint's `headers`)
injects the value, so the client only ever holds a placeholder; a secret
reference anywhere else in a rule is a compile error. Secrets are resolved
when roxy starts and on reload, and a secret that is missing or empty is a
fatal start or reload error. At evaluation time a missing secret fails the
flow closed (`_fail_closed`, reason `secret_missing`), and so does one that
is not a valid header value (`secret_invalid`). Every injected value is
redacted from the flow log and capture heads. `roxy check` and `roxy rule
test` do not resolve secrets.

```yaml
secrets:
  openai: { env: OPENAI_API_KEY }
  gh:     { file: /run/secrets/github_token }   # one trailing newline (`\n` or `\r\n`) stripped; warns if group or world can read it

rules:
  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }
      - allow
```

The client can send any placeholder in `authorization`; `set_header`
replaces it before the request is forwarded.
