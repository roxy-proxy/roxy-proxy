#!/bin/sh
# Checks the quickstart end to end without an Anthropic key: roxy and the
# sentinel start, a fake model's tool calls are passed or blocked by the
# sentinel, roxy's rules deny other hosts, and the sentinel has no route
# out of its own. CI runs it on each image build (image.yml).
#
#   ./test.sh                     # pulls ghcr.io/roxy-proxy/roxy:edge
#   ROXY_IMAGE=roxy:test ./test.sh
#
# ROXY_TEST_OFFLINE=1 skips the checks that need the internet behind roxy.
set -u
cd "$(dirname "$0")"

work=$(mktemp -d)
# The real policy plus one rule for the fake model (rules come last in
# roxy.yaml, so appending adds to them).
cat roxy.yaml - > "$work/roxy.yaml" <<'YAML'

  - id: test-fake-model
    when: host == "fake-model" and port == 8082
    then: { allow: { private_ok: true } }
YAML
export ROXY_TEST_CONFIG="$work/roxy.yaml"
compose() { docker compose -f compose.yaml -f compose.test.yaml "$@"; }

failed=0
ok() { printf '  \033[32mok\033[0m    %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; failed=1; }
finish() {
    if [ "$failed" != 0 ]; then compose logs --no-color; fi
    compose down -v >/dev/null 2>&1
    rm -rf "$work"
}
trap finish EXIT

compose build sentinel || exit 1
compose up -d --wait --no-build || { failed=1; exit 1; }

curl -fsS http://127.0.0.1:3130/roxy-ca.pem -o "$work/ca.pem" \
    && ok "roxy's CA is served on 127.0.0.1:3130" || bad "no CA on 127.0.0.1:3130"

# ask PROMPT [EXTRA]: a model call through roxy; the body lands in $work/out.
ask() {
    curl -sS -x http://127.0.0.1:3128 -o "$work/out" -w '%{http_code}' --max-time 60 \
        -H 'content-type: application/json' http://fake-model:8082/v1/messages \
        -d "{\"model\":\"m\",\"max_tokens\":100,\"messages\":[{\"role\":\"user\",\"content\":\"$1\"}]${2:-}}"
}
expect() { # LABEL STATUS GOT PATTERN
    if [ "$3" = "$2" ] && grep -q "$4" "$work/out"; then ok "$1"; else bad "$1 (got $3: $(head -c 200 "$work/out"))"; fi
}

echo "The sentinel judges each tool call before the client sees it:"
expect "a benign tool call (ls) passes"              200 "$(ask 'list files')"                '"tool_use"'
expect "a curl tool call is blocked"                 200 "$(ask 'do evil')"                   "sentinel blocked a Bash tool call"
expect "... and streamed"                            200 "$(ask 'do evil' ',"stream":true')"  "sentinel blocked a Bash tool call"
if grep -q '"tool_use"' "$work/out"; then bad "the blocked stream still carries the tool call"; fi

echo "roxy's rules decide which hosts are reachable:"
s=$(curl -sS -x http://127.0.0.1:3128 --cacert "$work/ca.pem" -o "$work/out" -w '%{http_code}' --max-time 20 https://example.com/)
expect "example.com is denied by default"            403 "$s"                                 '"rule":"_default"'
if [ "${ROXY_TEST_OFFLINE:-0}" != 1 ]; then
    s=$(curl -sS -x http://127.0.0.1:3128 --cacert "$work/ca.pem" -o "$work/out" -w '%{http_code}' --max-time 30 \
        -H 'x-api-key: not-a-key' -H 'anthropic-version: 2023-06-01' -H 'content-type: application/json' \
        https://api.anthropic.com/v1/messages -d '{"model":"claude-haiku-4-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}')
    expect "api.anthropic.com is reached (401: no key)" 401 "$s"                                 'authentication_error'
fi

echo "The sentinel's network has no route out:"
if docker run --rm --network roxy-quickstart_sidecar roxy-quickstart-sentinel python -c \
    "import urllib.request; urllib.request.urlopen('https://example.com/', timeout=10)" 2>/dev/null; then
    bad "a direct request from the sidecar network got through"
else
    ok "a direct request from the sidecar network fails"
fi

echo "Both keep a record, and the viewer shows the sentinel's:"
sleep 3   # the sentinel writes its Inspect log every 2s
s=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:7575/)
[ "$s" = 200 ] && ok "inspect view is up on 127.0.0.1:7575" || bad "inspect view answered $s"
events=$(compose exec -T inspect-view python -c "
from inspect_ai.log import list_eval_logs, read_eval_log
log = read_eval_log(list_eval_logs('/logs')[0])
print(sum(e.event == 'sentinel' and e.action == 'reject' for s in log.samples for e in s.events))
" 2>&1)
[ "$events" -ge 2 ] 2>/dev/null && ok "the Inspect log has the rejections ($events)" \
    || bad "the Inspect log has no rejections: $events"
compose logs --no-log-prefix roxy | grep -q '"terminal_rule":"_default"' \
    && ok "roxy's flow log has the deny" || bad "the deny is not in roxy's flow log"
compose logs --no-log-prefix sentinel | grep -q '"event": "sentinel_report"' \
    && ok "the sentinel recorded its decisions" || bad "no sentinel records"

exit $failed
