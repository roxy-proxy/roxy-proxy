# Running without Docker

```sh
cargo build --release
B=./target/release/roxy

$B check --config roxy.yaml      # validate; exits 1 with diagnostics
$B run   --config roxy.yaml      # start; edits to the file hot-reload
```

A minimal `roxy.yaml`, which allows `GET`/`HEAD` to `example.com` and denies
everything else:

```yaml
version: 1
listeners:
  - name: proxy
    bind: 127.0.0.1:3128
tls:
  ca_dir: ./ca                 # writable; the CA is generated here
rules:
  - id: example
    when: host == "example.com" and method in [GET, HEAD]
    then: allow
```

Each GitHub release carries prebuilt binaries (static musl builds for
Linux).
