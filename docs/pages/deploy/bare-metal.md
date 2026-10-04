# Running without Docker

```sh
cargo build --release
B=./target/release/roxy

$B check --config examples/minimal.yaml      # validate; exits 1 with diagnostics
$B run   --config examples/minimal.yaml      # start; edits to the file hot-reload
```

`examples/minimal.yaml` allows `GET`/`HEAD` to `example.com` and denies
everything else. Set `tls.ca_dir` to a writable directory first. Each GitHub
release carries prebuilt binaries (static musl builds for Linux).
