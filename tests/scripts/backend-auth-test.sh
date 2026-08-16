#!/bin/sh
# =============================================================================
# backend-auth-test.sh — end-to-end test for the clinical-orders proxy's OPTIONAL
# upstream Authorization injection (PROXY_BACKEND_AUTHORIZATION).
#
# Hermetic (no full stack, no DB, no auth server, no APISIX). It stands up a
# throwaway echo upstream (the mock-auth catch-all, which reflects request headers)
# and runs the REAL clinical-orders proxy template
# (clinical-orders/clinical-orders-proxy.conf.template) in two nginx containers,
# then asserts what the proxy forwards UPSTREAM to the backend:
#
#   inject  PROXY_BACKEND_AUTHORIZATION set   → Authorization is overwritten with it
#   noop    PROXY_BACKEND_AUTHORIZATION empty → the caller's Authorization passes through
#
# Requires: docker, curl. Exits non-zero on the first failed assertion.
#
#   tests/scripts/backend-auth-test.sh
# =============================================================================
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NGINX_IMAGE="nginx:alpine"
ECHO_IMAGE="umzh-mock-auth-echo:test"
TEMPLATE="${ROOT}/clinical-orders/clinical-orders-proxy.conf.template"
NET="umzh-baauth-net-$$"
ECHO_CT="umzh-baauth-echo-$$"
INJECT_CT="umzh-baauth-inject-$$"
NOOP_CT="umzh-baauth-noop-$$"
ECHO_PORT="${ECHO_PORT:-18080}"
INJECT_PORT="${INJECT_PORT:-18091}"
NOOP_PORT="${NOOP_PORT:-18092}"

# Fixtures.
BACKEND_AUTH="Basic $(printf '%s' 'e2e-user:e2e-pass' | base64 | tr -d '\n')"
CALLER_BEARER="Bearer caller-token-should-pass-through"

cleanup() {
    docker rm -f "$INJECT_CT" "$NOOP_CT" "$ECHO_CT" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "============================================="
echo " clinical-orders proxy — backend-auth e2e test"
echo "============================================="

echo "--- building echo image (mock-auth) ---"
docker build -q -t "$ECHO_IMAGE" "${ROOT}/tests/mock-auth" >/dev/null

echo "--- creating network + echo upstream ---"
docker network create "$NET" >/dev/null
docker run -d --rm --name "$ECHO_CT" --network "$NET" --network-alias echo \
    -p "${ECHO_PORT}:8080" "$ECHO_IMAGE" >/dev/null

i=0
until curl -sf "http://localhost:${ECHO_PORT}/healthz" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -ge 20 ] && { echo "echo upstream never came up"; exit 1; }
    sleep 1
done
echo "    echo upstream ready"

# Run the real proxy template twice: once WITH a backend credential, once without.
# This test only exercises backend-auth injection; the transport knobs point the
# proxy at the echo upstream (plain http, path /fhir so /fhir/ping stays /fhir/ping).
run_proxy() {  # run_proxy <container> <host-port> <PROXY_BACKEND_AUTHORIZATION>
    docker run -d --rm --name "$1" --network "$NET" -p "$2:8080" \
        -e PROXY_UPSTREAM="echo:8080" \
        -e PROXY_SCHEME="http" \
        -e PROXY_BACKEND_HOST="echo" \
        -e PROXY_BACKEND_PATH="/fhir" \
        -e PROXY_BACKEND_AUTHORIZATION="$3" \
        -e NGINX_ENVSUBST_FILTER="PROXY_" \
        -v "${TEMPLATE}:/etc/nginx/templates/default.conf.template:ro" \
        "$NGINX_IMAGE" >/dev/null
}

echo "--- starting proxy (inject: credential set) ---"
run_proxy "$INJECT_CT" "$INJECT_PORT" "$BACKEND_AUTH"
echo "--- starting proxy (noop: credential empty) ---"
run_proxy "$NOOP_CT" "$NOOP_PORT" ""

for pair in "inject:${INJECT_PORT}" "noop:${NOOP_PORT}"; do
    port="${pair#*:}"; name="${pair%:*}"
    i=0
    until curl -sf -H "Authorization: probe" "http://localhost:${port}/fhir/ping" >/dev/null 2>&1; do
        i=$((i + 1)); [ "$i" -ge 20 ] && { echo "proxy '$name' never came up"; exit 1; }
        sleep 1
    done
done
echo "    both proxies ready"

fail=0
assert_contains() {  # <label> <haystack> <needle>
    if printf '%s' "$2" | grep -qF -- "$3"; then echo "  PASS  $1"; else
        echo "  FAIL  $1"; echo "        expected: $3"; echo "        in:       $2"; fail=1; fi
}
assert_absent() {    # <label> <haystack> <needle>
    if printf '%s' "$2" | grep -qF -- "$3"; then
        echo "  FAIL  $1"; echo "        unexpected: $3"; echo "        in:       $2"; fail=1
    else echo "  PASS  $1"; fi
}

echo ""
echo "--- inject : PROXY_BACKEND_AUTHORIZATION set → injected upstream ---"
# Send a caller bearer to prove it is OVERWRITTEN (never leaks to the backend).
INJECT=$(curl -s -H "Authorization: ${CALLER_BEARER}" "http://localhost:${INJECT_PORT}/fhir/ping")
assert_contains "upstream Authorization == configured backend credential" "$INJECT" "\"$BACKEND_AUTH\""
assert_absent   "caller bearer does NOT reach the backend"                "$INJECT" "caller-token-should-pass-through"

echo ""
echo "--- noop : PROXY_BACKEND_AUTHORIZATION empty → caller header passes through ---"
NOOP=$(curl -s -H "Authorization: ${CALLER_BEARER}" "http://localhost:${NOOP_PORT}/fhir/ping")
assert_contains "caller Authorization passes through unchanged" "$NOOP" "$CALLER_BEARER"
assert_absent   "no backend credential injected when empty"     "$NOOP" "e2e-user"

echo ""
echo "============================================="
[ "$fail" -eq 0 ] && echo " RESULT: backend-auth e2e PASSED" || echo " RESULT: FAILURES"
echo "============================================="
exit "$fail"
