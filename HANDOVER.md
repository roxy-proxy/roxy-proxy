# roxy handover

Outstanding work is tracked as GitHub issues: start at
**https://github.com/roxy-proxy/roxy-proxy/issues/1**. That tracking issue
has the working rules for agents, the conflict zones and the suggested
merge order. Each sub-issue (#2–#15) is scoped for one agent.

State of `main` (2026-10-03): the head/watching rule model (DESIGN.md §6.1)
and the buffered flow log writer with end-to-end audit backpressure
(§10.1) are merged; CI green, 387 tests.

Open decision for the maintainer: keep or drop proxy auth
(`listeners[].auth`). Note that addons use `client.user` from proxy auth as
the trusted principal (§11.3), so dropping it leaves only `client.ip`.

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
