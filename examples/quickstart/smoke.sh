#!/usr/bin/env bash
# Runs the quickstart stack and waits for each control to fire in the
# traffic's log: the quota's 429 for alice, the auth gate's 401 for mallory
# and the sentinel's blocked tool call. CI runs this
# (.github/workflows/quickstart.yml); it takes a few minutes the first time.
#   ./smoke.sh            # builds, checks, tears down
#   KEEP=1 ./smoke.sh     # leaves the stack running
set -euo pipefail
cd "$(dirname "$0")"

docker compose up -d --build --wait
if [[ -z "${KEEP:-}" ]]; then
    trap 'docker compose down -v' EXIT
fi

wanted=(
    '^\[alice #[0-9]+\] 429 RateLimitError: token bucket empty'
    '^\[mallory #1\] 401 AuthenticationError'
    "^\[(alice|bob) #[0-9]+\] tool call: Bash \{'command': 'ls -la'\}"
    "sentinel blocked a Bash tool call \(denylist match: 'curl'\)"
)
deadline=$((SECONDS + 150))
while :; do
    log=$(docker compose logs --no-log-prefix traffic)
    missing=()
    for want in "${wanted[@]}"; do
        grep -qE -- "$want" <<<"$log" || missing+=("$want")
    done
    [[ ${#missing[@]} == 0 ]] && break
    if (( SECONDS >= deadline )); then
        echo "smoke: not seen after 150s:" >&2
        printf '  /%s/\n' "${missing[@]}" >&2
        echo "$log" >&2
        exit 1
    fi
    sleep 5
done
echo "$log"

# Every model call went through all three layers, in order.
flows=$(docker compose logs --no-log-prefix roxy)
grep -qE '"addons":\["auth-gate","token-quota","sentinel"\]' <<<"$flows" \
    || { echo "smoke: no flow went through all three addons" >&2; exit 1; }
echo "smoke: ok"
