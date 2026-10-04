# Secrets

`secrets:` maps names to an environment variable or a file. `${secret:name}`
in a request `set_header` value (or an addon endpoint's `headers`) injects
the value, so the client only ever holds a placeholder. Secrets are resolved
when roxy starts and on reload; a missing one at evaluation time fails the
flow closed. Every injected value is redacted from the flow log and capture
heads. `roxy check` and `roxy rule test` do not resolve secrets.

```yaml
secrets:
  openai: { env: OPENAI_API_KEY }
  gh:     { file: /run/secrets/github_token }   # one trailing newline stripped

rules:
  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }
      - allow
```

The client can send any placeholder in `authorization`; `set_header`
replaces it before the request is forwarded.
