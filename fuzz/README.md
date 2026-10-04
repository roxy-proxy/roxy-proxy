# Fuzzing roxy

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) targets
for the code that parses untrusted input. `fuzz/` is its own workspace, so
the main build, CI and `cargo deny` never see it, and it needs nightly only
to run.

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked

python3 fuzz/generate_seeds.py   # writes fuzz/seeds/<target>/
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run h1_request corpus/h1_request seeds/h1_request -- -max_total_time=300
```

The first directory is the working corpus, which grows as the fuzzer runs.
`seeds/<target>` holds the generated seeds. Both are git-ignored.

| target | code | invariants beyond "never panics" |
|---|---|---|
| `h1_request` | `roxy-http` `h1::scan_head` / `parse_head` | Scanning is resumable. The canonical form is a fixed point: parse, serialise (`src/lib.rs`), parse and serialise again give the same bytes. |
| `h1_chunked` | `h1::ChunkedDecoder` | The result does not depend on how input is split into reads, and the output is never longer than the input. |
| `h2map` | `h2map::from_h2_parts` | An accepted request has the tunnel's authority and a normalised path, and no reserved (hop-by-hop, framing, routing) header. |
| `ws_frame` | `roxy-http` `ws::frame::Decoder` | The result does not depend on how input is split into reads. No message is over its limit. Re-encoding the messages as roxy relays them and decoding again gives the same messages, without error. |
| `url` | `url::*` | Path, query, origin-form, absolute-form and authority normalisation are idempotent. A normalised path starts with `/` and has no `.` or `..` segment, `%2E`-encoded or not. |
| `client_hello` | `roxy-tls` `sniff` | Reading more never changes a verdict: over an input's prefixes, `NeedMore` until one constant answer. |
| `rule_compile` | `roxy-rules` lexer, parser, type-checker, compiler | A policy that compiles evaluates without panicking, and a fail-closed outcome is never an allow. |
| `content_coding` | `roxy-http` `coding::Decoder` (gzip, deflate, br, zstd, stacked) | The result does not depend on how input is fed or output read, and the decoded-size limit holds exactly: a body of `n` decoded bytes is refused under a limit of `n - 1`. |
| `rule_eval` | `Policy::evaluate_head` on generated policies | **Unavailable inputs only ever fail closed.** Making one input unavailable (a metric, the body text, the address list) leaves the outcome exactly as it was, or turns it into the fail-closed deny, never into a different decision. |
| `dns_query` | `roxy-dns` `parse`, `answer`, `error` | Every reply fits in 512 bytes, carries the query's id and echoes the question as sent, and is itself dropped by `parse`, so roxy never answers an answer. |

The input format is in each target's doc comment. For the HTTP targets the
first byte selects the parser flags and the role (see `src/lib.rs`).

To check that `rule_eval`'s differential property actually bites: make
`MapView::metric` report a missing metric as `Some(0)` (a fail-open bug)
and run it. It finds a counterexample within a few hundred executions.

## Seeds

`python3 fuzz/generate_seeds.py` generates `seeds/` from the project's own
vectors, so the seeds are never stale and nothing derived is checked in:

- **`h1_request`, `h1_chunked`:** the 168-case smuggling corpus in
  `crates/roxy-http/tests/corpus`, with each case's role and flags in the
  config byte.
- **`url`:** request targets from that corpus.
- **`client_hello`:** real ClientHellos from Python's `ssl`.
- **`rule_compile`:** every `when:` expression in `examples/` and
  `crates/roxy-rules`.
- **`content_coding`:** a small stream in each coding (gzip and zlib from
  Python's standard library, br and zstd as fixed bytes), a stacked pair,
  and gzip with every optional header field.
- **`ws_frame`:** the RFC 6455 example frames and a fragmented, masked
  message with a ping in the middle.
- **`dns_query`:** A, AAAA and HTTPS queries, with and without EDNS, and a
  few malformed shapes.

## CI

`.github/workflows/fuzz.yml` runs every target:

- **Nightly:** 5 minutes each, continuing from the corpus earlier runs grew
  (kept in the Actions cache, minimised with `cmin`).
- **Pull requests** that touch a fuzzed parser or `fuzz/`: 60 seconds each.
- **On demand:** `workflow_dispatch`, for a chosen number of seconds.

A failure uploads the reproducer as the `fuzz-crash-<target>` artifact.
Reproduce it with `cargo +nightly fuzz run <target> <file>`. Then fix it, and
add the input as a regression test in the crate it points at: for example a
case in `roxy-http/tests/corpus`, or a unit test next to the code.

`crates/roxy-http/tests/fuzz_smoke.rs` runs the h1 and URL invariants on
stable with proptest, as part of `cargo test`.
