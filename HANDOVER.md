# roxy handover (2026-10-03, updated)

State for the next working session. Read DESIGN.md first; it is the spec.
Delete this file once its contents are done.

## On `main`

Usable explicit-proxy firewall: M1 plus the agreed parts of M2, now on the
**new rule model** (DESIGN.md §6.1):

- One rule list; deny wins over allow; `default: deny | allow`; the
  implicit allow grants no options.
- Head rules decide at the request head. Watching rules (`body.bytes`,
  `response.*`, deny rules on `request_bytes` / `response_bytes` metrics)
  are re-checked by a per-exchange watcher before each body chunk is
  forwarded, at the response head (response header effects) and in the
  WebSocket relay. A stop answers with an error response if nothing was
  sent; otherwise h1 breaks the connection, h2 resets with `CANCEL`
  (+ `GOAWAY` if the deny closes), the WebSocket relay closes both sides.
- No connect-time rules; CONNECT is accepted for inspection (auth + SNI).
- Flow log `stage` field; `roxy check` and `roxy rule test` print each
  rule's classification; `rule test` has `--body-bytes`,
  `--response-status`, `--response-body-bytes`; `run` refuses `ws.*`.
- 381 tests (fmt, clippy `-D warnings`, full suite twice green).
- Benchmarks (criterion, this container): 100-rule head decision 3.4 µs;
  per-chunk watching check with no match ~100 ns; a chunk no rule watches
  ~13 ns; metric record ~220 ns, get ~410 ns.

Decision taken, matching DESIGN.md §6.1/§6.4: only byte metrics make a
deny rule watch; a deny on `requests`/`denied`/`errors`/`unique` is a head
rule (so `>= 30` still denies the 31st request).

Known limitation: the WebSocket relay is byte-level, so a stop closes both
sides without a `1008` close frame (§6.3). Proxy auth and the CA endpoint
are M2 items from earlier sessions; the user asked about proxy auth and has
not decided whether to keep it.

## Next, in order (agreed with the user)

1. **Buffered log writer with end-to-end backpressure** (DESIGN.md §10.1,
   "Writing"). One writer task per sink, bounded queue, batched writes; a
   full queue makes emitting wait, which must propagate to the network
   (slow traffic, never drop audit records). `FlowSink::emit` likely
   becomes async (or returns a permit future) and its callers on the
   exchange path await it. Same machinery later for body capture / teeing.
2. **Release + container image.** GitHub Actions: on a tag, build release
   binaries and publish a GitHub release; build a static (musl) binary into
   a hardened image (distroless static or scratch, non-root) pushed to
   GHCR.
3. **README as a quickstart** around a docker compose example: an app
   container on an `internal: true` network with no route out (egress is
   enforced by the Docker network, not by the proxy variables), roxy the
   only container on both that network and an egress network, the app
   given `HTTP(S)_PROXY` and roxy's CA. Show that direct egress fails.
4. Later, with addons (M4): a basic inspect-sentinel example layer (deny
   tool calls by regex on the request body; show where an LLM/classifier
   call would plug in, no actual LLM calls).

## Agreed scope and what's deferred

Stop at a usable explicit proxy (M1 plus essential M2). These are deferred,
with designs in DESIGN.md:

- addons, now called layers (§11): wasm and service kinds, observe mode,
  named endpoints, terminate via a quarantine gate, and the
  inspect_sentinel mapping in §11.7;
- WebSocket message rules (§8.2);
- transparent mode (§4.2);
- body capture and a Prometheus endpoint;
- making `limits.max_metric_bytes` configurable (it is fixed at 256 MiB).

## Environment

- Remote: `git@github.com:roxy-proxy/roxy-proxy.git`, over SSH (HTTPS has no
  credential helper). There is no `gh`.
- On the user's machine the repo is on `/mnt/c` (slow builds). Always set
  `CARGO_TARGET_DIR` under `$HOME/.cache`, and give each parallel agent its
  own target directory. The machine has 7 GB of RAM.
- The workspace needs rustc 1.99 (`rustup update stable`).
- Commit as you go, ending messages with the attribution trailer. Build
  agents work in worktrees; review, merge and verify each one before
  pushing.
