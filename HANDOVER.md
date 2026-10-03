# roxy handover (2026-10-03)

State at handover, for the next working session. Read DESIGN.md first; it is
the spec. Delete this file once its contents are done.

## On `main` (pushed, CI green)

Usable explicit-proxy firewall, all of M1 and the agreed parts of M2:

- Strict HTTP/1.1 codec (168-case smuggling corpus), client-side HTTP/2 via
  ALPN, TLS interception with roxy's own CA.
- Rule DSL with `null` semantics. A missing value equals only `null`, and any
  operator other than `== != in not in` on `null` fails closed with
  `missing_value`.
- Metric and state stores. There is no eviction: a full table or an
  exhausted byte budget denies.
- Address denylists. Rule membership is exact, and the deny floor is broad
  (NAT64 and 6to4 forms are caught).
- Private-range floor, WebSocket relay, proxy auth, CA download endpoint.
- Hot reload, `roxy check`, `roxy rule test`.
- 362 tests pass. They run with
  `CARGO_TARGET_DIR=$HOME/.cache/roxy-target-main`, prefixed with
  `. "$HOME/.cargo/env" &&`.

**Still on main:** the OLD rule model, with phases and first-match-wins.

## In flight: the new rule model (not merged)

A build agent started the new model and stopped at roughly 25%. Its work is
one WIP commit, `99d2ff6`, pushed to **`origin/wip/rule-model`** (also the
local branch `worktree-agent-a83c098c259da14a7`, worktree
`.claude/worktrees/agent-a83c098c259da14a7`). It changes only
`crates/roxy-rules/src/*` and **does not compile yet**: nothing has been
built or tested.

**Drafted in the WIP:**

- **Config.** `Phase` is removed. The new `default:` key and
  `DefaultDecision` are added, and a `phase` key is rejected with a pointer
  to the design.
- **Fields.** The `dst.*` fields are removed and `body.bytes` /
  `response.body.bytes` are added. A `Reads` bitmask classifies what each
  rule reads.
- **Precedence.** `Policy::evaluate_head` has deny-wins precedence, the
  first matching explicit allow's options, and an implicit allow that grants
  no options.
- **Watching.** `Policy::evaluate_watching` handles change triggers. Each
  rule's effects apply once, and any error or deny stops the exchange.
- **Compile errors.** Added for: `allow` in a watching rule; request
  mutation or `${secret:}` in a watching rule; a response `set_header` that
  could fire after the response head is sent; and metric `where`, `key` or
  `unique()` reading non-head fields.

**Still to do:**

1. **Finish roxy-rules.**
   - `metrics.rs`: drop `Phase`. `Sample` gains `head`; requests and
     `unique` count at the head, bytes count incrementally, errors at the
     end.
   - Leftover `Phase` references in `eval.rs`; `MapView` needs the new
     fields.
   - All tests, snapshots and benches, plus the new engine tests listed in
     the spec.
2. **roxy-proxy (not started).**
   - Remove `ConnectGate`, `dst` facts and `Phase` from sources.
   - Add a per-exchange watcher: a counting body adapter that evaluates
     **before yielding each chunk**, and a cancellation token selected
     against the upstream future.
   - Response head and response body checks, with response header effects
     applied before the head is written.
   - Stop behaviour:
     - h1: break the connection mid-body (no terminating chunk);
     - h2: `RST_STREAM(CANCEL)`, plus GOAWAY if `close`;
     - WebSocket relay: evaluate before each write, and close both sides.
   - A `stage` field in the flow log.
3. **CLI.**
   - Wire `default:` into `PolicyInput`.
   - `run` refuses `ws.*` rules.
   - `rule test` drops `--phase` and gains `--response-status`,
     `--body-bytes` and `--response-body-bytes`.
   - `check` prints the rule classification.
   - Update the CLI and config tests.
4. **End-to-end tests.**
   - Port the connect-phase tests, the address-list test (use `client.ip`)
     and the response-5xx test.
   - Add tests for: upload cap over h1 and h2; response byte cap over h1
     and h2; byte budget; WebSocket budget; `run` refusing `ws.*`;
     `rule test` output.
5. **Examples.**
6. **Finish.** fmt, clippy, the full test suite twice, benchmark numbers,
   then split into logical commits.

**Decision taken in the WIP, worth confirming with the user:** only
`request_bytes` / `response_bytes` metrics make a deny rule watch. A deny
reading `requests`, `denied`, `errors` or `unique` stays a head rule:
re-checking it after this exchange's own +1 would deny the 30th request of a
`>= 30` limit instead of the 31st. This matches DESIGN.md §6.4.

**DESIGN.md updates the agent proposed:**

- §6.1: state the narrowed watching rule above.
- §6.3: `set_header` / `remove_header` in a watching rule target the
  response, and are legal only when everything that can re-check the rule is
  known before the response head is sent.
- §6.4: metric `key` and `unique()` fields must be head fields.
- §3: "Key runtime types" still shows per-phase chains.

**Spec.** DESIGN.md §6.1 to §6.4, §4.3 and §8 on main. In short:

1. **No phases.**
   - A config with a `phase` key is a parse error pointing at §6.1.
   - Connect-time rules and the `dst.*` fields are removed.
   - `passthrough` stays reserved.
2. **Head rules versus watching rules.**
   - Rules reading only head fields are decided at the request head.
   - These rules are *watching*, and are re-checked as values arrive:
     - rules that read watched fields (`body.bytes`, `response.*`,
       `response.body.bytes`, `ws.*`);
     - `deny` rules that read a metric this exchange adds to.
   - Watching rules can only deny or add effects. Using `allow` or mutating
     the request in one is a compile error.
   - A watching deny stops the exchange:
     - with an error response if the response has not started;
     - otherwise h1 closes the connection, h2 resets the stream (plus
       GOAWAY if `close`), and a WebSocket relay closes both sides.
   - A watching rule's effects apply once.
   - The flow log gets a `stage` field.
3. **Deny wins.** Precedence, highest first:
   1. any matching deny (`terminal_rule` is the first matching deny in
      list order);
   2. any matching allow (the first matching allow);
   3. `default: deny | allow` (default `deny`, rule id `_default`).

   Further:
   - Rule order affects only effects and tags, never the decision.
   - If the request is allowed, every matching rule's effects apply in list
     order, and the later one wins.
   - Allow options (`upgrade`, `private_ok`) come from the **first matching
     explicit allow only**. The implicit allow under `default: allow`
     grants **no** options.
   - Every head rule is evaluated, so a fail-closed reason in any of them
     fails the request.
4. **Response header effects.** `set_header` and `remove_header` in a rule
   that reads response values apply to the response.
5. **Byte metrics count as bytes stream.** `request_bytes` and
   `response_bytes` are recorded incrementally, including for the WebSocket
   relay. A metric `where` filter may read head fields only.
6. **WebSocket message rules are not built.** `ws.*` compiles, but `roxy run`
   and reload refuse such a policy, while `roxy check` accepts it.
   `allow: { inspect }` is removed.
7. **CLI.**
   - `roxy rule test` loses `--phase` and gains `--body-bytes`,
     `--response-body-bytes` and `--response-status`.
   - Both `rule test` and `roxy check` print whether each rule is a head
     rule or watching, and why.
8. **Examples.** Remove `phase`, and add a streaming upload-cap watching
   rule.

**Review checklist before merging** (the user's priority is containment over
availability; audit the code, don't trust the report):

- No request body chunk is forwarded after a watching deny matched on it:
  evaluation happens before each chunk is forwarded.
- No error in watching evaluation lets the exchange continue.
- A missing value in a watching rule fails closed and stops the exchange.
- The implicit allow grants no options.
- Per-chunk evaluation does not allocate and is skipped when no watching
  rule reads the changed value.
- Everything stays green: fmt, clippy with `-D warnings`, and the full test
  suite twice.

**After merging:**

- Commit the README rewrite. It is **uncommitted in the main checkout** and
  already describes the new model. Check it against what was built.
- Apply the DESIGN.md changes the agent reports.
- Push.

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
- The repo is on `/mnt/c` (slow builds). Always set `CARGO_TARGET_DIR` under
  `$HOME/.cache`, and give each parallel agent its own target directory.
  The machine has 7 GB of RAM.
- Commit as you go, ending messages with the attribution trailer. Build
  agents work in worktrees; review, merge and verify each one before
  pushing.
