#!/usr/bin/env bash
# Builds the example addons as components and copies them next to their
# sources (e.g. sentinel/sentinel.wasm), where roxy's tests and examples
# load them. Needs the wasm32-wasip2 target:
#   rustup target add wasm32-wasip2
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
cargo build --release --target wasm32-wasip2
cp target/wasm32-wasip2/release/sentinel.wasm sentinel/sentinel.wasm
ls -l sentinel/sentinel.wasm
