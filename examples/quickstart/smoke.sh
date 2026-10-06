#!/usr/bin/env bash
# Runs the quickstart stack and checks each control fires: the quota's 429,
# the auth gate's 401 and the sentinel's blocked tool call. CI runs this
# (.github/workflows/quickstart.yml); it takes a few minutes the first time.
#   ./smoke.sh            # builds, checks, tears down
#   KEEP=1 ./smoke.sh     # leaves the stack running
set -euo pipefail
cd "$(dirname "$0")"

docker compose up -d --build --wait
if [[ -z "${KEEP:-}" ]]; then
    trap 'docker compose down -v' EXIT
fi
curl -fsS -X POST http://127.0.0.1:8090/reset >/dev/null

# The client's lines for a run; its exit status is checked by the caller.
client() {
    docker compose run --rm client "$@" 2>&1 | grep -E '^\[' || true
}
check() {
    if ! grep -qE -- "$2" <<<"$1"; then
        echo "smoke: expected /$2/ in:" >&2
        echo "$1" >&2
        exit 1
    fi
}

alice=$(client --user alice --repeat 6)
echo "$alice"
[[ $(grep -c '\] 200 ' <<<"$alice") == 5 ]] || { echo "smoke: expected five 200s" >&2; exit 1; }
check "$alice" '^\[alice #6\] 429 RateLimitError: token quota exhausted'
check "$alice" "tool call: Bash \{'command': 'ls -la'\}"
check "$alice" "sentinel blocked a Bash tool call \(denylist match: 'curl'\)"

bob=$(client --user bob)
echo "$bob"
check "$bob" '^\[bob #1\] 200 '

mallory=$(client --user mallory --secret wrong)
echo "$mallory"
check "$mallory" '^\[mallory #1\] 401 AuthenticationError'

# Every model call went through all three layers, in order.
flows=$(docker compose logs --no-log-prefix roxy)
check "$flows" '"addons":\["auth-gate","token-quota","sentinel"\]'
echo "smoke: ok"
