#!/usr/bin/env bash
# Rebuilds the roxy-wasm test components and refreshes the checked-in
# fixtures in ../tests/fixtures/. Needs the wasm32-wasip2 target:
#   rustup target add wasm32-wasip2
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
cargo build --release --locked --target wasm32-wasip2
mkdir -p ../tests/fixtures
for c in redact test_layer; do
    cp "target/wasm32-wasip2/release/$c.wasm" "../tests/fixtures/$c.wasm"
done
ls -l ../tests/fixtures
