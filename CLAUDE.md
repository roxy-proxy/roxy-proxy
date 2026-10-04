# Working on roxy

Notes for agents (and people) working in this repository.

## Picking up an issue

1. **Claim it before you start.** Comment on the issue saying you are taking
   it, and open a **draft** pull request for it straight away. Your first
   commit can be small (a plan, a stub, the first step). Link the issue from
   the PR description (`Closes #N`). Check first that nobody else has claimed
   it: a recent claim comment or an open PR means it is taken, so ask rather
   than duplicate the work.
2. **Iterate on the draft.** Commit in small, coherent steps and push after
   each one, so the PR always shows where the work is. Don't sit on a large
   local diff. Keep the PR description current: what is done, what is left,
   and any decision a reviewer should look at.
3. **Mark it ready for review when it is done.** Done means the issue's
   "done when" list is met, CI is green, and the description says what
   changed and anything moved, dropped or left for later. Then switch the PR
   from draft to ready.
4. **Stay with it once it is queued.** The repo merges through a merge
   queue. A maintainer turns on "merge when ready" when they are happy with
   the PR; don't turn it on yourself. From then until it merges, fix any CI
   failure that appears, on the PR or in the queue, and push the fix.
5. **Follow-up work gets an issue.** If you find something out of scope, open
   an issue for it (or note it on an existing one) instead of widening the PR.

One issue, one branch, one PR. If an issue turns out too big for one PR, say
so on the issue and split it.

## Before pushing

Run what CI runs (`.github/workflows/ci.yml`):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI also builds with `RUSTFLAGS=-D warnings`, so a warning fails the build.
Changes to the wasm components (`crates/roxy-wasm/test-components`,
`examples/addons`, `wit/`) also need the checks in CI's `wasm` job; the
built components are checked in, so rebuild them with the `build.sh` scripts
and commit the result. Changes to a fuzzed parser run the fuzz workflow on
the PR (`fuzz/README.md`).

## Code

- Rust workspace, stable toolchain, edition 2024. `unsafe` is forbidden and
  clippy runs at `pedantic`.
- Crates live in `crates/`: `roxy` (the binary), `roxy-http`, `roxy-proxy`,
  `roxy-rules`, `roxy-tls`, `roxy-log`, `roxy-wasm` (the addon host) and
  `roxy-addon` (the addon SDK).
- roxy is a security boundary. The design principles (fail closed, deny
  always wins, canonical re-serialisation, ...) are not negotiable for
  convenience: if a change weakens one, raise it on the issue first.
- Match the surrounding code: its naming, comment density and error style.
  Comments explain why, not what.
- Add tests with behaviour changes. A parser or rule-engine bug fix gets a
  regression test, and a fuzz finding becomes a test in the crate it hit.

## Docs

- `README.md` is the overview and quickstart; `docs/` is the reference for
  current behaviour. Code comments point at docs by page and section.
- Docs describe what roxy does now. No roadmap, "planned" or "deferred"
  prose: unbuilt work lives in issues.
- A change that alters behaviour updates the matching docs page in the same
  PR.
- Write plainly: short sentences, concrete statements, British spelling.
