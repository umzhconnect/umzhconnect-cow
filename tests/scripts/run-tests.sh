#!/bin/sh
# =============================================================================
# run-tests.sh — integration test runner for this single-party node.
#
#   1. wait for services
#   2. run the unauthenticated suite (health, registry read-only, auth negatives)
#   3. if the mock auth issuer is up (test overlay), seed the placer fixtures,
#      run placer.hurl + fulfiller.hurl, then tear the fixtures down
#
# Auth is pluggable via TOKEN_SOURCE (default mock). With the mock, bring the
# stack up WITH the test overlay so the gateway trusts the mock issuer:
#
#   keys/gen-keys.sh l2
#   docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build
#   tests/scripts/run-tests.sh
#
# To run the SAME tests against a real auth server, bring up the base stack
# (no overlay) and set TOKEN_SOURCE=real (+ CLIENT_ID, and CALLER_ORG/OUR_ORG to
# the registered client's org). The runner then mints via the L2 flow instead.
#
# JUnit XML → tests/reports/. Exit non-zero if any executed file fails.
# =============================================================================
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HURL_DIR="${SCRIPT_DIR}/../hurl"
REPORT_DIR="${SCRIPT_DIR}/../reports"
mkdir -p "$REPORT_DIR"

GATEWAY_URL="${GATEWAY_URL:-http://localhost:9081}"
REGISTRY_URL="${REGISTRY_URL:-http://localhost:9084}"
CUSTODIAN_URL="${CUSTODIAN_URL:-http://localhost:9087}"
OPA_URL="${OPA_URL:-http://localhost:9181}"
MOCK_AUTH_URL="${MOCK_AUTH_URL:-http://localhost:9099}"
PROXY_URL="${PROXY_URL:-http://localhost:9091}"
TOKEN_SOURCE="${TOKEN_SOURCE:-mock}"
# Test org identities. CALLER_ORG (the reading fulfiller in placer.hurl) MUST
# match the Consent actor the seed writes; OUR_ORG is the Task owner in fulfiller.hurl.
CALLER_ORG="${CALLER_ORG:-http://localhost:9084/fhir/Organization/HospitalA}"
OUR_ORG="${OUR_ORG:-http://localhost:9084/fhir/Organization/HospitalB}"
SR_ID="${SR_ID:-sr-e2e}"
PAT_ID="${PAT_ID:-pat-e2e}"
export GATEWAY_URL REGISTRY_URL CUSTODIAN_URL OPA_URL PROXY_URL CALLER_ORG
export MOCK_AUTH_URL TOKEN_SOURCE

echo "============================================="
echo " umzhconnect-cow — integration tests"
echo "============================================="
"$SCRIPT_DIR/wait-for-services.sh"

fail=0
run() {  # run <hurl-file> [extra --variable args...]
    name="$(basename "$1")"
    echo ""
    echo "--- $name ---"
    if hurl --test --report-junit "${REPORT_DIR}/${name}.xml" \
        --variable "gateway_url=${GATEWAY_URL}" \
        --variable "registry_url=${REGISTRY_URL}" \
        --variable "custodian_url=${CUSTODIAN_URL}" \
        --variable "opa_url=${OPA_URL}" \
        "$@"; then :; else fail=1; fi
}

# --- Unauthenticated suite (always) ---
run "${HURL_DIR}/01-health.hurl"
run "${HURL_DIR}/02-registry-readonly.hurl"
run "${HURL_DIR}/03-auth-negative.hurl"

# --- Role scenarios (need an auth source to mint tokens) ---
if [ "$TOKEN_SOURCE" = "mock" ]; then
    auth_probe="${MOCK_AUTH_URL}/healthz"; auth_hint="bring up docker-compose.test.yml"
else
    auth_probe="${CUSTODIAN_URL}/healthz"; auth_hint="start the stack and set CLIENT_ID"
fi

if curl -sf --max-time 5 "$auth_probe" > /dev/null 2>&1; then
    echo ""
    echo "=== auth source '${TOKEN_SOURCE}' up → seeding fixtures + minting tokens ==="
    sh "$SCRIPT_DIR/seed.sh" up
    trap 'sh "$SCRIPT_DIR/seed.sh" down' EXIT

    PLACER_TOKEN=$(SCOPE="system/ServiceRequest.r system/Patient.r" ORG_REF="${CALLER_ORG}" \
        CONTEXT_REF="ServiceRequest/${SR_ID}" sh "$SCRIPT_DIR/get-token.sh" || true)
    FULFILLER_TOKEN=$(SCOPE="system/Task.c system/Task.r system/Task.s system/Task.u" \
        ORG_REF="${OUR_ORG}" sh "$SCRIPT_DIR/get-token.sh" || true)

    if [ -n "$PLACER_TOKEN" ]; then
        run "${HURL_DIR}/placer.hurl" \
            --variable "token=${PLACER_TOKEN}" \
            --variable "sr_id=${SR_ID}" \
            --variable "pat_id=${PAT_ID}"
    else
        echo "--- placer.hurl: SKIPPED (could not mint token) ---"; fail=1
    fi

    if [ -n "$FULFILLER_TOKEN" ]; then
        run "${HURL_DIR}/fulfiller.hurl" \
            --variable "token=${FULFILLER_TOKEN}" \
            --variable "our_org=${OUR_ORG}"
    else
        echo "--- fulfiller.hurl: SKIPPED (could not mint token) ---"; fail=1
    fi
else
    echo ""
    echo "--- placer.hurl / fulfiller.hurl: SKIPPED (auth source '${TOKEN_SOURCE}' not reachable) ---"
    echo "    ${auth_hint}"
fi

echo ""
echo "============================================="
[ "$fail" -eq 0 ] && echo " RESULT: all executed suites passed" || echo " RESULT: FAILURES (see reports)"
echo "============================================="
exit "$fail"
