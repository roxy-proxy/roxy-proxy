#!/usr/bin/env bash
# Rebuilds the roxy-wasm test components and refreshes the checked-in
# fixtures in ../tests/fixtures/. Needs the wasm32-wasip2 target:
#   rustup target add wasm32-wasip2
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
# The copies below come from this directory, whatever the caller's CARGO_TARGET_DIR.
export CARGO_TARGET_DIR="$here/target"
# The bytes must not depend on the machine. Cargo hashes the absolute path
# of a dependency outside the workspace (roxy-addon) into the build, so
# build through a fixed path; rustc embeds source paths, so remap them.
build=/tmp/roxy-proxy-build
ln -sfn "$(cd ../../.. && pwd)" "$build"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$build=/roxy --remap-path-prefix=$cargo_home=/cargo"
cargo build --release --locked --target wasm32-wasip2 \
    --manifest-path "$build/crates/roxy-wasm/test-components/Cargo.toml"
mkdir -p ../tests/fixtures
for c in redact test_layer; do
    cp "target/wasm32-wasip2/release/$c.wasm" "../tests/fixtures/$c.wasm"
done
ls -l ../tests/fixtures
