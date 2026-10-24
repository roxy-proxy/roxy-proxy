# Secrets

`secrets:` maps names to where their values come from. `${secret:name}`
in a rule's `set_header` value, in `sign` credentials, or in an addon
endpoint's `headers` injects the value, so the client only ever holds a
placeholder. A reference anywhere else is a compile error.

```yaml
secrets:
  openai: { env: OPENAI_API_KEY }
  gh:     { file: /run/secrets/github_token }   # one trailing newline is stripped
  lease:  { lease: true }                       # supplied by the control plane

rules:
  - id: openai
    when: host == "api.openai.com" and path starts_with "/v1/" and method == POST
    then:
      - set_header: { authorization: "Bearer ${secret:openai}" }   # replaces whatever the client sent
      - allow
```

- Each secret has exactly one of `env`, `file` or `lease: true`.
- `env` and `file` are read at startup and on reload. A missing or empty
  value stops roxy starting, or fails a reload. `roxy check` and
  `roxy rule test` do not read them.
- Injected values are masked in the flow log and in captured headers:
  each byte becomes `*`.
- A `redirect` sends the request, injected values included, to the new
  target. Make sure a rule that injects a secret cannot match a request
  that another rule redirects elsewhere.

## Redacting responses

An upstream can echo an injected value back, for example in an error page
that quotes `authorization`, or in a `location` header that carries a key.
The client would then see the real value. `http.redact_response_secrets`
masks it in the response:

```yaml
http:
  redact_response_secrets:
    headers: true      # response header and trailer values
    bodies: true       # the response body, as it streams
    quarantine: false  # quarantine roxy when a secret is found
    min_length: 8      # shorter values are not masked
```

All three switches are off by default.

- **What is masked:** only the values that this exchange's `set_header`
  actions filled in from `${secret:..}`. A secret roxy did not put in the
  request is left alone. Values that `sign` sends (the access key id and
  session token) are not masked, because neither works without the secret
  key, which never leaves roxy.
- **How:** each byte becomes `*`, so a value keeps its length. An
  uncompressed body keeps its `content-length`.
- **`min_length`** (at least 1): shorter values are not masked, since a
  short value would match unrelated text.
- **Headers:** every header and trailer value, including a `101`'s.
  Header names are not changed.
- **Bodies:** masked as they stream. Only bytes that could be the start of
  a secret wait for the next chunk, so streams such as server-sent events
  are not delayed.
- **Compressed bodies:** roxy decompresses the body, masks it and
  compresses it again in the same coding
  ([content codings](/reference/http#content-codings)). A body roxy cannot
  decompress is refused with `503` and reason
  `unsupported_content_encoding` rather than sent unmasked.
- **Ranges:** with `bodies` on, roxy drops `range` and `if-range` from a
  request that injected a secret, so the upstream sends the whole body. A
  range could cut a secret so that no whole copy of it is in the
  response, and the client chooses where the range starts and ends. A
  partial response (`206`) that comes back anyway is refused with `503`
  and reason `partial_response`.
- **Who sees it masked:** addons and the client. The response rules,
  `response.body.text`, the in-flight byte counts and the capture see the
  response as the upstream sent it, so a captured body holds an echoed
  secret ([capture](/reference/flow-log#capture)).
- **`quarantine: true`** quarantines roxy when a secret is found, with the
  cause `{"kind": "secret_in_response", "flow", "part"}`, where `part` is
  `headers`, `body` or `trailers` ([quarantine](/guides/operations#quarantine)).
  A secret in the headers refuses that exchange; one in the body is masked.
  It needs `headers` or `bodies` on, and `roxy run --state-dir`. Without
  it, a found secret is logged as a warning.
- **Limits:** the match is on the exact bytes, so a value the upstream
  changes (base64, escaping, a change of case) is not caught. This stops
  careless echoes, not a hostile upstream: choosing which hosts get a
  secret is the real control. WebSocket messages are not masked.

## Signing AWS requests

The `sign` action signs the forwarded request with AWS Signature Version
4, so a client holding placeholder credentials reaches AWS with a real
signature.

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

- roxy signs the request as it is forwarded, after every other change the
  rules make, wherever `sign` appears in `then`. It removes any signature
  headers the client sent first.
- `service` is the AWS signing name, such as `bedrock`, `s3` or
  `execute-api`. S3 services get S3's variant of the signature.
- A request with a presigned URL (`X-Amz-Signature` in the query) is
  forwarded under the client's signature, not roxy's. The rule's `host`
  and `path` conditions still limit where it can go.
- The body is buffered, up to `limits.max_sign_body_bytes` (100 MiB), to
  hash it. A larger body is refused with `413`. For S3,
  `unsigned_payload: true` skips the hash and streams the body.
- If two matching rules both sign, the request is denied
  (`sign_conflict`).

## Lease secrets

`name: { lease: true }` declares a secret that the control plane supplies
with the lease ([node protocol](/reference/node-protocol#lease-body)). It
is held in memory only, never on disk. `roxy run --config` refuses a
config that declares one. When the control plane changes a secret, the
next request uses the new value, while an exchange in progress keeps the
value it started with.
