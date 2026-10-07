# Secrets

`secrets:` maps names to where each value comes from. `${secret:name}` in a
head rule's `set_header` value or `sign` credentials, or in an addon
endpoint's `headers`, injects the value, so the client only ever holds a
placeholder; a secret reference anywhere else in a rule is a compile error.

```yaml
secrets:
  openai: { env: OPENAI_API_KEY }
  gh:     { file: /run/secrets/github_token }   # one trailing newline (`\n` or `\r\n`) stripped; warns if group or world can read it
  lease:  { lease: true }                       # supplied by the control-plane lease

rules:
  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }   # replaces whatever the client sent
      - allow
```

- A secret has exactly one of `env`, `file` or `lease: true`; `{}`, `null`,
  a bare word and `lease: false` are parse errors.
- `env` and `file` secrets are resolved when roxy starts and on reload; one
  that is missing or empty is a fatal start or reload error.
- At evaluation time a missing secret fails the flow closed
  (`_fail_closed`, reason `secret_missing`), and so does one that is not a
  valid header value (`secret_invalid`).
- Every injected value is redacted from the flow log and capture heads.
- `roxy check` and `roxy rule test` do not resolve secrets.

## Signing AWS requests

`sign: { aws_sigv4: ... }` is a head-rule action that signs the outgoing
request with AWS Signature Version 4, so a client holding placeholder
credentials reaches AWS with real ones. The three credential fields take
`${secret:name}` under the same rules as `set_header` values;
`session_token` is optional.

```yaml
secrets:
  aws_akid:  { env: AWS_ACCESS_KEY_ID }
  aws_sk:    { env: AWS_SECRET_ACCESS_KEY }
  aws_token: { env: AWS_SESSION_TOKEN }

rules:
  - id: bedrock
    when: host under "bedrock-runtime.eu-west-2.amazonaws.com" and scheme == "https"
    then:
      - sign:
          aws_sigv4:
            service: bedrock
            region: eu-west-2
            access_key_id: "${secret:aws_akid}"
            secret_access_key: "${secret:aws_sk}"
            session_token: "${secret:aws_token}"   # optional
      - allow
```

- **What is signed.** The request as it is forwarded, after every other
  head effect (`set_header`, `rewrite_path`, `redirect`, ...), whatever the
  action's position in `then`. The client's `authorization`, `x-amz-date`,
  `x-amz-security-token` and `x-amz-content-sha256` are removed first.
  `host` is always signed, as it goes upstream. Never signed: the hop-by-hop
  and framing fields roxy re-serialises (`connection`,
  `transfer-encoding`, `content-length`, `accept-encoding`, `te`,
  `trailer`, `upgrade`, `keep-alive`, `proxy-connection`), and `user-agent`
  and `x-amzn-trace-id`, which intermediaries change. Every other header
  is. A header whose value is not UTF-8 (obs-text, under
  `http.allow_obs_text`) cannot be signed: the request is refused with
  `400` (`terminal_rule: _sign`, `reason: sign_header_invalid`).
- **`service`** is the signing name (`bedrock`, `s3`, `execute-api`, ...).
  `s3`, `s3-control` and `s3-outposts` use the S3 variant (the path encoded
  once, not normalised, and the payload hash sent as
  `x-amz-content-sha256`).
- **Presigned requests.** A request whose query carries `X-Amz-Signature`
  goes out under the client's query signature, with the client's
  `authorization` and `x-amz-*` signature headers stripped and no signature
  of roxy's; `mutations` records `sign:presigned` in place of
  `sign:aws_sigv4`. Such a request reaches AWS as whoever signed the URL, so
  the rule's `host` and `path` conditions are what bound where it may go.
- **Two matching rules that both sign** fail the flow closed
  (`sign_conflict`).
- **Body.** The payload hash needs the whole body, so a request body is
  buffered up to `limits.max_sign_body_bytes` (100 MiB) before signing. A
  body over that, declared or chunked, is refused with `413`
  (`terminal_rule: _sign`, `reason: sign_body_too_large`) and the
  connection closed. `unsigned_payload: true` signs `UNSIGNED-PAYLOAD` and
  streams the body unbuffered; only S3 accepts it, so it is a config error
  with any other `service`.
- **Logging and tools.** `mutations` records `sign:aws_sigv4`; the injected
  credentials are redacted like any secret. `roxy rule test` shows the
  effect as `sign aws_sigv4 service=... region=...` without computing a
  signature; `roxy check` validates the block.

## Lease secrets

`name: { lease: true }` declares a secret the config does not resolve: the
control plane hands the value over in memory with the lease
([node protocol](/reference/node-protocol#lease-body)). `roxy check`
accepts the document; standalone `roxy run --config` has no lease and
refuses to start, naming the secret.

Secret values live in a store beside the compiled policy, not inside it.
Replacing the map swaps the store and rebuilds the redactor without
recompiling rules, rebuilding addons or flushing upstream pools, and
without a reload event. An exchange resolves every name from the generation
current at its head evaluation, so a swap landing mid-evaluation cannot
pair one credential with another's replacement; an exchange already under
way keeps the generation it injected, and redacts its log with it, however
many swaps follow. A name the policy references but the map lacks fails
the flow closed (`secret_missing`). Values never appear in the config file,
on disk or in logs. A config reload resolves `env` and `file` sources into
the same store and swaps the policy as usual.
