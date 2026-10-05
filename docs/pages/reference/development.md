# Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace            # unit, corpus, property and end-to-end tests
```

CI (`.github/workflows/ci.yml`) runs these with `RUSTFLAGS=-D warnings`,
plus `cargo deny` and a `wasm` job. The wasm test components
(`crates/roxy-wasm/test-components`) are their own
workspace and are checked in prebuilt, so the main jobs need no wasm
target; the `wasm` job rebuilds them from source and runs the tests that
load them, so the binaries cannot drift from their sources. After changing
one, rebuild it with its `build.sh` and commit the result.

The crates and how they fit together are in
[architecture](/reference/architecture#crates). [CLAUDE.md](https://github.com/roxy-proxy/roxy-proxy/blob/main/CLAUDE.md) has the
working practices for picking up issues.

## Testing

- **Smuggling corpus** (`crates/roxy-http/tests/corpus/`): CL.TE, TE.CL and
  TE.TE obfuscations, duplicate lengths, obs-fold, bare LF, `%2e%2e` path
  climbs, Host/authority mismatches, CRLF in header values, and more. Every
  case has an expected reason code. It is the acceptance test for the
  [rejection rules](/reference/http#rejection-rules).
- **Property tests:** URL normalisation is idempotent; serialise → parse
  round-trips to an equal canonical model.
- **Golden tests** (`insta`) for rule diagnostics
  (`crates/roxy-rules/tests/snapshots/`). Update them with
  `cargo insta review` when a message changes on purpose.
- **End-to-end tests** (`crates/roxy/tests/`): roxy, a local TLS upstream
  with a test CA, and HTTP/1.1, HTTP/2 and WebSocket clients, covering
  allow, deny, effects, metrics, reload, capture and addons.
- **Benchmarks** (`criterion`): rule evaluation for a 100-rule policy
  (target under 5 µs), metric recording, address-list lookups. Run with
  `cargo bench -p roxy-rules` or `-p roxy-proxy`.

## Fuzzing

`fuzz/` is a cargo-fuzz workspace (nightly; see
[fuzz/README.md](https://github.com/roxy-proxy/roxy-proxy/blob/main/fuzz/README.md)) with targets for:

- the HTTP/1.1 request head, where the canonical form is a fixed point of
  parse → serialise → parse;
- the chunked body decoder;
- the content-coding decoders;
- the h2 → canonical mapping;
- the URL normaliser (idempotent, no dot segments survive);
- the ClientHello sniffer (verdicts never change as more bytes arrive);
- the DNS query parser;
- the WebSocket frame decoder;
- the rule lexer, parser and compiler;
- policy evaluation, where making an input unavailable either changes
  nothing or fails closed, and never yields a different decision.

Seeds are generated from the smuggling corpus and the example configs.
`.github/workflows/fuzz.yml` runs every target nightly (5 minutes each,
growing a cached corpus) and for 60 seconds on pull requests that touch a
fuzzed parser. A crash becomes a regression test in the crate it hit.

## Releasing

Push a `vX.Y.Z` tag; see [RELEASING.md](https://github.com/roxy-proxy/roxy-proxy/blob/main/RELEASING.md).
