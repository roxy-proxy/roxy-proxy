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

A build agent was implementing the new model on branch
`worktree-agent-a83c098c259da14a7`. Its worktree is
`.claude/worktrees/agent-a83c098c259da14a7`. At handover it had **no commits**:

- **Engine:** uncommitted changes in `crates/roxy-rules/src/{compile,config,policy,types}.rs`.
- **Proxy and CLI:** not started.

If that agent did not finish, either continue from its worktree or start
again from the spec below.

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
