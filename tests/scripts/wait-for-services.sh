#!/bin/sh
# =============================================================================
# wait-for-services.sh — block until THIS node's services answer.
# URLs come from env (defaults match .env.example host ports). The auth issuer is
# probed by run-tests.sh itself (mock in tests, external in real deployments).
# =============================================================================
MAX_WAIT="${MAX_WAIT:-120}"
INTERVAL=3

GATEWAY_URL="${GATEWAY_URL:-http://localhost:9081}"
REGISTRY_URL="${REGISTRY_URL:-http://localhost:9084}"
CUSTODIAN_URL="${CUSTODIAN_URL:-http://localhost:9087}"
OPA_URL="${OPA_URL:-http://localhost:9181}"
PROXY_URL="${PROXY_URL:-http://localhost:9091}"

wait_for() {
    name="$1"; url="$2"; elapsed=0
    printf "  %-26s" "$name..."
    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        if curl -sf --max-time 5 "$url" > /dev/null 2>&1 || wget -q --spider --timeout=5 "$url" > /dev/null 2>&1; then
            echo " OK (${elapsed}s)"; return 0
        fi
        sleep "$INTERVAL"; elapsed=$((elapsed + INTERVAL))
    done
    echo " TIMEOUT after ${MAX_WAIT}s"; return 1
}

echo "=== Waiting for services ==="
wait_for "External gateway"       "${GATEWAY_URL}/healthz"
wait_for "Registry"               "${REGISTRY_URL}/fhir/metadata"
wait_for "Clinical-orders proxy"  "${PROXY_URL}/fhir/metadata"
wait_for "Key custodian"          "${CUSTODIAN_URL}/healthz"
wait_for "OPA"                    "${OPA_URL}/health"
echo "=== Services ready ==="
