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
- Injected values are removed from the flow log and from captured headers.
- A `redirect` sends the request, injected values included, to the new
  target. Make sure a rule that injects a secret cannot match a request
  that another rule redirects elsewhere.

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
