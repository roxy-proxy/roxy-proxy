# Secrets

`secrets:` maps names to sources. `${secret:name}` in a head rule's
`set_header` value or `sign` credentials, or an addon endpoint's `headers`,
injects the value; the client holds only a placeholder. A reference
anywhere else is a compile error.

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

- Exactly one of `env`, `file`, `lease: true`; `{}`, `null`, a bare word
  and `lease: false` are parse errors.
- `env` and `file` resolve at start and on reload; missing or empty is
  fatal. `roxy check` and `roxy rule test` do not resolve secrets.
- At evaluation, a missing secret fails closed (`_fail_closed`, reason
  `secret_missing`); one that is not a valid header value, `secret_invalid`.
- Injected values are redacted from the flow log and capture heads.

## Signing AWS requests

`sign: { aws_sigv4: ... }`, a head-rule action, signs the forwarded request
with AWS Signature Version 4, so a client holding placeholder credentials
reaches AWS with a real signature. Credential fields take `${secret:name}` as
`set_header` does; `session_token` is optional.

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

- **Signed:** the request as forwarded, after every other head effect
  (`set_header`, `rewrite_path`, `redirect`, ...) whatever `sign`'s
  position in `then`. The client's `authorization`, `x-amz-date`,
  `x-amz-security-token` and `x-amz-content-sha256` are removed first.
  `host` is signed as sent upstream. Not signed: `connection`,
  `transfer-encoding`, `content-length`, `accept-encoding`, `te`,
  `trailer`, `upgrade`, `keep-alive`, `proxy-connection` (re-serialised by
  roxy), `user-agent`, `x-amzn-trace-id` (changed by intermediaries).
  Every other header is. A non-UTF-8 header value (obs-text, under
  `http.allow_obs_text`) is refused with `400` (`terminal_rule: _sign`,
  `reason: sign_header_invalid`).
- **`service`** is the signing name (`bedrock`, `s3`, `execute-api`, ...).
  `s3`, `s3-control` and `s3-outposts` use the S3 variant: path encoded
  once, not normalised; payload hash sent as `x-amz-content-sha256`.
- **Presigned:** a request whose query carries `X-Amz-Signature` goes out
  under the client's query signature, its `authorization` and `x-amz-*`
  signature headers stripped, no signature of roxy's; `mutations` records
  `sign:presigned`. It reaches AWS as whoever signed the URL; the rule's
  `host` and `path` conditions bound where it may go.
- **Two matching rules that both sign** fail closed (`sign_conflict`).
- **Body:** buffered up to `limits.max_sign_body_bytes` (100 MiB) for the
  payload hash; over that, declared or chunked, is `413` (`terminal_rule:
  _sign`, `reason: sign_body_too_large`) and the connection closed.
  `unsigned_payload: true` signs `UNSIGNED-PAYLOAD` and streams the body;
  only S3 accepts it, so it is a config error with any other `service`.
- **Tools:** `mutations` records `sign:aws_sigv4`; the credentials are
  redacted like any secret. `roxy rule test` shows `sign aws_sigv4
  service=... region=...` without computing a signature; `roxy check`
  validates the block.

## Lease secrets

`name: { lease: true }` declares a secret the control plane supplies in
memory with the lease ([node protocol](/reference/node-protocol#lease-body)).
`roxy check` accepts it; standalone `roxy run --config` refuses to start,
naming the secret.

Values live in a store beside the compiled policy. Replacing the map swaps
the store and rebuilds the redactor without recompiling rules, rebuilding
addons, flushing upstream pools or a reload event. An exchange resolves
every name from the generation current at its head evaluation, so a swap
mid-evaluation cannot pair one credential with another's replacement; an
exchange under way keeps the generation it injected, and redacts with it,
however many swaps follow. A name the map lacks is `secret_missing`. Values
never appear in the config file, on disk or in logs. A config reload
resolves `env` and `file` sources into the same store.
