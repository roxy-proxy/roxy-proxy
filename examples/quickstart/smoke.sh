#!/usr/bin/env bash
# Runs the quickstart stack and checks it end to end: roxy denies everything
# until its first lease, a host no rule allows is denied, each control fires
# in the traffic's log (the quota's 429 for alice, the auth gate's 401 for
# mallory, the sentinel's blocked tool call), the control plane receives the
# flow log, a layer whose service is gone fails the call closed, a lease that
# runs down denies everything until the control plane is back, and the
# standalone override runs the same policy from the file. CI runs this
# (.github/workflows/quickstart.yml); it takes a few minutes the first time.
#   ./smoke.sh            # builds, checks, tears down
#   KEEP=1 ./smoke.sh     # leaves the stack running
set -euo pipefail
cd "$(dirname "$0")"

# A short lease so expiry is quick to observe; the compose default is 60.
export LEASE_VALID_SECONDS="${LEASE_VALID_SECONDS:-20}"

fail() { echo "smoke: $*" >&2; exit 1; }

# `<status> <body>` of roxy's /readyz, or `000` while it is not listening.
readyz() {
    local out
    out=$(curl -s -m 2 -w ' %{http_code}' http://127.0.0.1:3130/readyz 2>/dev/null) || { echo 000; return; }
    awk '{print $NF, $1}' <<<"$out"
}

# Polls readyz until it answers `$1`, for up to `$2` seconds.
wait_readyz() {
    local want=$1 deadline=$((SECONDS + $2)) got
    while :; do
        got=$(readyz)
        [[ $got == "$want" ]] && return
        (( SECONDS >= deadline )) && fail "/readyz is '$got', wanted '$want' after $2s"
        sleep 1
    done
}

# The status and x-roxy-rule of a POST through the proxy to `$1` (the model
# by default), with any further arguments passed to curl.
proxied() {
    local url=${1:-http://fake-model:8080/v1/messages}
    shift || true
    curl -s -m 20 -o /dev/null -D - -x http://127.0.0.1:3128 -X POST "$@" "$url" \
        | awk 'NR==1 {s=$2} tolower($1)=="x-roxy-rule:" {r=$2} END {printf "%s %s\n", s, r}' | tr -d '\r'
}

# `proxied` as a client the auth gate knows.
as_alice() { proxied "${1:-}" -H 'x-roxy-auth: alice-secret'; }

# Fails unless `$1` (a proxied result) matches the regex `$2`.
expect() { [[ $1 =~ $2 ]] || fail "proxied request answered '$1', wanted /$2/"; }

docker compose build
if [[ -z "${KEEP:-}" ]]; then
    trap 'docker compose down -v' EXIT
fi

# roxy with no control plane to lease from: up, but not ready. The control
# plane runs once first so the CA certificate roxy verifies it with exists.
docker compose up -d --wait controlplane
docker compose stop controlplane
docker compose up -d --no-deps roxy
wait_readyz "503 no_policy" 30
echo "smoke: no policy before the first lease"

docker compose up -d --wait
wait_readyz "200 ready" 5
echo "smoke: lease applied"

# No rule allows any host but the model, so the default deny answers.
expect "$(as_alice http://example.com/)" '^403 _default$'
echo "smoke: default deny"

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
    || fail "no flow went through all three addons"

# The flow log reached the control plane: one line per event, node id first.
shipped=$(docker compose logs --no-log-prefix controlplane)
grep -qE '^node-[0-9a-f]+ \{.*"event":"request"' <<<"$shipped" \
    || fail "no flow event on the control plane's stdout"

# A layer that cannot reach its service fails the call closed, not open.
docker compose stop quota-board
expect "$(as_alice)" '^503 '
docker compose start quota-board
echo "smoke: fail closed without the quota board"

# With the control plane gone the lease runs down and roxy denies everything.
docker compose stop controlplane
wait_readyz "503 policy_expired" $((LEASE_VALID_SECONDS + 30))
got=$(proxied)
[[ $got == "403 _expired" ]] || fail "proxied request during expiry answered '$got', wanted '403 _expired'"
echo "smoke: lease expired"

# The control plane coming back recovers roxy without a restart. The lease
# client backs off up to 60s between attempts.
docker compose start controlplane
wait_readyz "200 ready" 120
got=$(proxied)
[[ $got != "403 _expired" ]] || fail "proxied request still '_expired' after recovery"
echo "smoke: lease recovered"

# The standalone override: the same policy from the file, with the secret
# from roxy's own environment and no control plane.
docker compose -f compose.yaml -f compose.standalone.yaml up -d --wait
wait_readyz "200 ready" 30
expect "$(as_alice)" '^200 model-api$'
echo "smoke: standalone"
echo "smoke: ok"
