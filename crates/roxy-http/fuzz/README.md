# roxy-http fuzz targets

`cargo-fuzz` targets for the parsers that see attacker-controlled bytes
(`DESIGN.md` §14.2). This directory is its own Cargo workspace and is **not**
a member of the main workspace, because `cargo fuzz` needs a nightly
toolchain.

| target | what it checks |
|---|---|
| `h1_head` | `scan_head` / `parse_head` never panic under every flag/role combination; incremental scanning agrees with one-shot scanning |
| `h1_chunked` | `ChunkedDecoder` never panics, never emits more bytes than it was fed, and gives the same result however the input is split |
| `url_normalize` | `normalize_path`, `normalize_query`, `parse_origin_form`, `parse_absolute_form`, `parse_authority` never panic and are idempotent |

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

cd crates/roxy-http
cargo +nightly fuzz run h1_head
cargo +nightly fuzz run h1_chunked
cargo +nightly fuzz run url_normalize

# Fixed budget (CI): 60 s per target
cargo +nightly fuzz run h1_head -- -max_total_time=60
```

Seed corpora can be taken from `tests/corpus/*.txt` (unescape the raw
sections). Crashes land in `fuzz/artifacts/<target>/`; reproduce with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`.
