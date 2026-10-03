#!/bin/sh
# Shows what the quickstart's agent can and cannot do. Run after
# `docker compose up -d --wait` in this directory. Exits non-zero if any
# expectation fails.
#
# ROXY_DEMO_OFFLINE=1 skips the checks that need the real internet behind
# roxy (an allowed request, the upload cap); the containment checks and the
# policy denials work without it.
set -u
cd "$(dirname "$0")"

failed=0
ok() { printf '  \033[32mok\033[0m    %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; failed=1; }
agent() { docker compose exec -T agent "$@"; }
# HTTP status of a request from the agent (000 if it never got one).
status() { agent curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$@" 2>/dev/null; }

echo "Through roxy (the agent's HTTPS_PROXY), roxy's policy decides:"
if [ "${ROXY_DEMO_OFFLINE:-0}" != 1 ]; then
    s=$(status https://example.com/)
    [ "$s" = 200 ] && ok "GET https://example.com/ is allowed (200)" \
        || bad "GET https://example.com/ should be 200, got $s"
fi
s=$(status https://www.wikipedia.org/)
[ "$s" = 403 ] && ok "GET https://www.wikipedia.org/ is denied by default (403)" \
    || bad "GET https://www.wikipedia.org/ should be 403, got $s"
body=$(agent curl -sS --max-time 20 https://example.com/admin/ 2>/dev/null)
case $body in
    *'"rule":"no-admin-paths"'*) ok "GET https://example.com/admin/ is denied by rule no-admin-paths" ;;
    *) bad "GET https://example.com/admin/ should be denied by no-admin-paths, got: $body" ;;
esac
if [ "${ROXY_DEMO_OFFLINE:-0}" != 1 ]; then
    s=$(agent sh -c 'head -c 2000000 /dev/zero | curl -sS -o /dev/null -w "%{http_code}" --max-time 30 \
        -X POST --data-binary @- https://postman-echo.com/post' 2>/dev/null)
    [ "$s" = 413 ] && ok "a 2 MB upload is stopped by the streaming cap (413)" \
        || bad "a 2 MB upload should be stopped with 413, got $s"
fi

echo "Around roxy (ignoring the proxy settings), there is no route at all:"
if agent curl -sS -o /dev/null --max-time 10 --noproxy '*' https://example.com/ 2>/dev/null; then
    bad "a direct request to https://example.com/ got through"
else
    ok "a direct request to https://example.com/ fails"
fi
if agent curl -sS -o /dev/null --max-time 10 --noproxy '*' https://1.1.1.1/ 2>/dev/null; then
    bad "a direct connection to 1.1.1.1:443 got through"
else
    ok "a direct connection to 1.1.1.1:443 fails"
fi

if [ "${ROXY_DEMO_OFFLINE:-0}" != 1 ]; then
    # Control: the same direct request from a container on roxy's egress
    # network works, so the failures above are the sandbox network's doing.
    if docker run --rm --network roxy-quickstart_egress curlimages/curl:8.17.0 \
        -sS -o /dev/null --max-time 20 https://example.com/ 2>/dev/null; then
        ok "(control) the same request from the egress network works"
    else
        bad "(control) a direct request from the egress network should work"
    fi
fi

echo "Every decision is in roxy's flow log (docker compose logs roxy):"
if docker compose logs --no-log-prefix roxy | grep -q '"terminal_rule":"no-admin-paths"'; then
    ok "the no-admin-paths deny is logged"
else
    bad "the no-admin-paths deny is not in the flow log"
fi

exit $failed
