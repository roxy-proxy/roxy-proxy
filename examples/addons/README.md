# Example roxy addons

Addons are layers that sit above roxy's rules in each exchange
([docs/addons.md](../../docs/addons.md)). Whatever an addon passes on is still judged by the rules,
and any failure denies the flow.

| example | kind | what it shows |
|---|---|---|
| [`redact`](redact) | wasm (Rust, [`roxy-addon`](../../crates/roxy-addon)) | Rewriting both bodies chunk by chunk as they stream, holding back only the bytes a match could straddle. |

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
