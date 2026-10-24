# Secrets

`secrets:` maps names to sources. `${secret:name}` in an admission rule's
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
- Injected values are redacted from the flow log and capture heads, and,
  with `http.redact_response_secrets`, masked in the responses of the
  exchanges that injected them ([below](/reference/secrets#redacting-responses)).
- A `redirect` in a matching rule sends the request, injected values
  included, to the redirect target: a secret's `set_header` rule should
  not match a request another rule redirects elsewhere.

## Redacting responses

An upstream that echoes an injected value back (an error page quoting
`authorization`, a debug endpoint, a redirect carrying a key in its
`location`) hands the client the real value. `http.redact_response_secrets`
masks it in the response on its way out:

```yaml
http:
  redact_response_secrets:
    headers: true      # the response head's field values, and its trailers
    bodies: true       # the response body, as it streams
    quarantine: false  # quarantine the process when a masked part held a secret
    min_length: 8      # values shorter than this many bytes are not masked
```

- **What:** the values the exchange's own `set_header` effects
  substituted from `${secret:..}`, and nothing else: a secret roxy did not
  put into the request is not the client's to be kept from. `sign` is not
  covered: of its credentials, only the access key id and the session
  token are sent, and neither is usable without the secret access key,
  which never leaves roxy. Each byte of each occurrence becomes `*`, so
  every length stays as the upstream sent it. `headers`, `bodies` and
  `quarantine` are off by default.
- **`min_length`** (default 8, at least 1): a value shorter than this is
  not masked, since a short value would mask unrelated bytes wherever it
  happens to occur.
- **Headers:** every field value of the response head, a `101`'s
  included, and every trailer value. Names are left as they are.
- **Bodies:** masked as they stream. A chunk that ends in what could be
  the start of a secret has those bytes (at most `longest secret - 1`)
  held back until the next chunk shows whether the rest follows; nothing
  else is buffered or delayed. A body keeps its declared length.
- **Content codings:** with `bodies` on, an injecting request goes out
  without `accept-encoding`, so the upstream answers uncompressed. A
  response that is encoded anyway is decoded
  ([content codings](/reference/http#content-codings)) and sent without
  `content-encoding` or a declared length. One in a coding roxy does not
  decode, or a `206` (or `content-range`) of an encoded body, is refused
  `503` (`terminal_rule: _fail_closed`, `reason:
  unsupported_content_encoding`) instead of passed unmasked. A `206` of a
  plain body is masked range by range, its ranges unchanged: a secret
  split across two ranges is in neither whole, so each range passes its
  part.
- **Downstream of the upstream:** the masking happens in the core, after
  the response rules. The in-flight rules on the response body, the
  capture log, the addon layers (given the decoded body whatever
  `http.decode_for_addons` says) and the client all see the masked
  response. The response rules, and `response.body.text`, see it as the
  upstream sent it.
- **`quarantine: true`** quarantines the process when a masked part held
  a secret: the `quarantined` event's cause is `{"kind":
  "secret_in_response", "flow", "part"}`, `part` being `headers`, `body` or
  `trailers` ([quarantine](/guides/operations#quarantine)). A secret in the
  head refuses that exchange `_quarantined`; one in the body is masked in
  what is sent, and the connection is cut a second later with every
  other. It needs `headers` or `bodies` on (a config error otherwise) and
  `roxy run --state-dir`, as any quarantine does. Without it, a found
  secret is logged as a warning on the operational log, with the flow and
  the part.
- **Limits:** the match is on the exact bytes. An upstream that transforms
  the value (base64, JSON or URL escaping, a change of case) gets past it,
  so this stops careless echoes, not a hostile upstream; which hosts a
  secret is injected into is the real control. WebSocket messages after a
  `101` are not masked.

## Signing AWS requests

`sign: { aws_sigv4: ... }`, an admission-rule action, signs the forwarded request
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

- **Signed:** the request as forwarded, after every other admission effect
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
every name, in its rules and in the `headers` of the endpoint calls its
addons make, from the generation current at its admission evaluation, so a swap
mid-evaluation cannot pair one credential with another's replacement; an
exchange under way keeps the generation it injected, and redacts with it,
however many swaps follow. A name the map lacks is `secret_missing`. Values
never appear in the config file, on disk or in logs. A config reload
resolves `env` and `file` sources into the same store.
