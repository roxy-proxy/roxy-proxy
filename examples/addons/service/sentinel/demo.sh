#!/usr/bin/env bash
# End to end on one machine: a fake model API, roxy with the sidecar as a
# service layer, and an "agent" (curl) asking for a benign and a harmful
# tool call, plain and streamed.
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

"$py" "$here/fake_anthropic.py" 8082 & pids+=($!)
SENTINEL_LISTEN=127.0.0.1:9001 "$py" "$here/sidecar.py" > "$work/sentinel.jsonl" & pids+=($!)
"$roxy" run --config "$work/roxy.yaml" > "$work/roxy.log" 2>&1 & pids+=($!)
sleep 5

ask() {
  curl -s --noproxy '' -x http://127.0.0.1:3128 -o "$work/out" -w '%{http_code}' \
    -H 'content-type: application/json' http://127.0.0.1:8082/v1/messages \
    -d "{\"model\":\"m\",\"max_tokens\":100,\"messages\":[{\"role\":\"user\",\"content\":\"$1\"}]$2}"
}
check() {
  local got
  got="$(ask "$2" "$3")"
  printf '%-28s %s  %s\n' "$1" "$got" "$(head -c 80 "$work/out" | tr '\n' ' ')"
  [ "$got" = "$4" ]
}
check "benign tool call"          "list files" ""                 200
check "curl tool call"            "do evil"    ""                 403
check "benign, streamed"          "list files" ',"stream":true'   200
check "curl tool call, streamed"  "do evil"    ',"stream":true'   403
echo "sentinel records:"
cut -c1-160 "$work/sentinel.jsonl"
