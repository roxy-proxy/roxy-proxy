#!/usr/bin/env bash
# Builds the example addons as components and copies them next to their
# sources (e.g. redact/redact.wasm), where roxy's tests and examples
# load them. Needs the wasm32-wasip2 target:
#   rustup target add wasm32-wasip2
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
cargo build --release --target wasm32-wasip2
for name in redact; do
    cp "target/wasm32-wasip2/release/$name.wasm" "$name/$name.wasm"
    ls -l "$name/$name.wasm"
done
