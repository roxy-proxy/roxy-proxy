# Example roxy addons

Addons are layers that sit above roxy's rules in each exchange
(DESIGN.md §11). Whatever an addon passes on is still judged by the rules,
and any failure denies the flow.

| example | kind | what it shows |
|---|---|---|
| [`redact`](redact) | wasm (Rust, [`roxy-addon`](../../crates/roxy-addon)) | Rewriting both bodies chunk by chunk as they stream, holding back only the bytes a match could straddle. |
| `inspect-sentinel` (with service layers, #8) | service (Python sidecar) | [inspect_sentinel](https://github.com/meridianlabs-ai/inspect_sentinel) monitors and protocols judging LLM traffic at the network boundary. roxy implements its `Host` and `Recorder`. |
| `inspect-sentinel-wasm` (future) | wasm (CPython component) | The same sentinel compiled into a component, once inspect_sentinel has an embedded build. The host side is ready: raise `max_memory` and `max_exchange_time` for an embedded interpreter. |

## Building

The wasm examples form their own Cargo workspace (here) and build for
`wasm32-wasip2`:

```sh
rustup target add wasm32-wasip2
./build.sh        # builds each component and copies it next to its source
cargo test        # the layers' logic, natively
```

The built `.wasm` files are checked in, because roxy's tests load them
(`crates/roxy-wasm/tests/`) and the main CI jobs have no wasm target. After
changing an example, rebuild it and commit the result. The `wasm` CI job
rebuilds every component and runs those tests against the fresh build.
