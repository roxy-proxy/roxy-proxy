# roxy-wasm test components

Small `roxy:addon` components used by `crates/roxy-wasm/tests/`.

- `test-layer` (world `layer`): a pass-through layer, chunk by chunk, that can
  also relay full duplex, deny, answer itself (at once, after reading part of
  the body, or after forwarding part of it to `next`), rewrite, loop, hog
  memory, call `next` twice, trap at various points, leak a body and call
  every host service. The request's `x-test` header picks the behaviour. A
  layer configured with `{"name": "a"}` reads `x-test-a` first, tags flows it
  passes on `via:a` and appends `a` to the forwarded `x-via`, so each layer of
  a stack can be driven separately.
- `tunnel-layer` (world `tunnel-layer`): relays an upgraded connection
  (tagging the flow `tunnel`, and `tunnel:<name>` when named).

## Why prebuilt fixtures

Building a component needs the `wasm32-wasip2` target, and CI (like most
contributors' machines) does not install it. The built components are
therefore checked in under `../tests/fixtures/` (about 200 KB in total), and
`cargo test` only reads them.

A `build.rs` that builds them when the target happens to be installed would
make the test inputs depend on the machine running the tests, and it would
put wit-bindgen in the main workspace's dependency graph.

This directory is its own Cargo workspace, outside the root one. After
changing a component or `wit/`, rebuild:

```sh
rustup target add wasm32-wasip2   # once
./build.sh
```

and commit the updated `.wasm` files alongside the source change.
