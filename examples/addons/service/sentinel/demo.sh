#!/usr/bin/env bash
# End to end on one machine: a fake model API, roxy with the sidecar as a
# service layer, and an "agent" (curl) asking for a benign and a harmful
# tool call, plain and streamed. Then the same with SENTINEL_ON_REJECT=explain,
# where a refused response becomes an assistant message instead of a 403.
#
#   python -m venv .venv && .venv/bin/pip install -r requirements.txt
#   cargo build -p roxy
#   PYTHON=.venv/bin/python ./demo.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../../../.."
py="${PYTHON:-python3}"
roxy="${ROXY:-$root/target/debug/roxy}"
work="$(mktemp -d)"
pids=()
trap 'kill "${pids[@]}" 2>/dev/null; rm -rf "$work"' EXIT

cat > "$work/roxy.yaml" <<YAML
version: 1
listeners: [{ name: proxy, bind: 127.0.0.1:3128 }]
tls: { ca_dir: $work/ca }
log: { flow: { path: $work/flow.jsonl } }
default: deny
rules:
  - id: model-api
    when: host == "127.0.0.1" and port == 8082
    then: { allow: { private_ok: true } }
addons:
  - name: sentinel
    kind: service
    endpoint: sidecar
    endpoints:
      sidecar: { url: "http://127.0.0.1:9001/", private_ok: true }
    limits: { first_byte_timeout: 30s }
YAML

sidecar() {
  SENTINEL_LISTEN=127.0.0.1:9001 SENTINEL_ON_REJECT="$1" "$py" "$here/sidecar.py" \
    >> "$work/sentinel.jsonl" 2>> "$work/sentinel.log" &
  sidecar_pid=$!; pids+=($sidecar_pid)
}
"$py" "$here/fake_anthropic.py" 8082 & pids+=($!)
sidecar deny
"$roxy" run --config "$work/roxy.yaml" > "$work/roxy.log" 2>&1 & pids+=($!)
sleep 5

ask() {
  curl -s --noproxy '' -x http://127.0.0.1:3128 -o "$work/out" -w '%{http_code}' \
    -H 'content-type: application/json' http://127.0.0.1:8082/v1/messages \
    -d "{\"model\":\"m\",\"max_tokens\":100,\"messages\":[{\"role\":\"user\",\"content\":\"$1\"}]$2}"
}
# check LABEL PROMPT EXTRA STATUS [TEXT]: the status, and TEXT in the body.
check() {
  local got
  got="$(ask "$2" "$3")"
  printf '%-34s %s  %s\n' "$1" "$got" "$(head -c 80 "$work/out" | tr '\n' ' ')"
  [ "$got" = "$4" ] && { [ -z "${5:-}" ] || grep -q "$5" "$work/out"; }
}
check "benign tool call"          "list files" ""                 200
check "curl tool call"            "do evil"    ""                 403
check "benign, streamed"          "list files" ',"stream":true'   200
check "curl tool call, streamed"  "do evil"    ',"stream":true'   403

kill "$sidecar_pid"; wait "$sidecar_pid" 2>/dev/null || true
sidecar explain
sleep 3
check "explain: benign"                "list files" ""               200 '"tool_use"'
check "explain: curl tool call"        "do evil"    ""               200 '"stop_reason": "end_turn"'
check "explain: curl, streamed"        "do evil"    ',"stream":true' 200 'not allowed here'
check "explain: no tool_use left"      "do evil"    ',"stream":true' 200 'message_stop'
! grep -q tool_use "$work/out" || { echo "explain left a tool_use in the stream"; exit 1; }
check "explain: slow evil, streamed"   "slow evil"  ',"stream":true' 200 'event: ping'
[ "$(grep -c '^event: message_start' "$work/out")" = 1 ] || { echo "message_start sent twice"; exit 1; }
check "explain: slow benign, streamed" "slow ls"    ',"stream":true' 200 '"tool_use"'
echo "sentinel records:"
cut -c1-160 "$work/sentinel.jsonl"
