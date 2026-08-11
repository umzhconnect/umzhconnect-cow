#!/bin/sh
# =============================================================================
# seed.sh up|down — manage the placer test fixtures in the clinical-orders
# partition via the INTERNAL proxy (:9091, no auth). Production never seeds
# clinical-orders; this is test-only, and `down` removes everything again.
#
#   up   — PUT Patient/pat-e2e, ServiceRequest/sr-e2e, Consent/consent-e2e
#          (a transaction; the Consent names CALLER_ORG as actor).
#   down — DELETE those three + sweep any leftover test Tasks
#          (identifier urn:umzhc:test|e2e). Best-effort.
#
# CALLER_ORG MUST equal the organization_reference the placer token carries, or
# OPA's consent check won't match. Keep it in sync with run-tests.sh.
# =============================================================================
set -eu
ACTION="${1:-up}"
DIR="$(cd "$(dirname "$0")" && pwd)/../seed"
PROXY_URL="${PROXY_URL:-http://localhost:9091}"
CALLER_ORG="${CALLER_ORG:-http://localhost:9084/fhir/Organization/HospitalA}"

render() { sed "s|__CALLER_ORG__|${CALLER_ORG}|g" "$1"; }

case "$ACTION" in
  up)
    render "${DIR}/placer-seed.json" | curl -sf -X POST \
      -H "Content-Type: application/fhir+json" --data-binary @- \
      "${PROXY_URL}/fhir" > /dev/null
    echo "seed: placer fixtures created (Patient/ServiceRequest/Consent)"
    ;;
  down)
    render "${DIR}/placer-teardown.json" | curl -s -X POST \
      -H "Content-Type: application/fhir+json" --data-binary @- \
      "${PROXY_URL}/fhir" > /dev/null 2>&1 || true
    echo "seed: fixtures removed"
    ;;
  *)
    echo "usage: seed.sh up|down" >&2; exit 1 ;;
esac
