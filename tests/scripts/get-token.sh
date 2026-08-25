#!/bin/sh
# =============================================================================
# get-token.sh — print one access token for a test scenario. Two sources, chosen
# by TOKEN_SOURCE so the same tests run against the mock OR a real auth server:
#
#   TOKEN_SOURCE=mock (default)
#       POST the mock issuer's /token with the EXACT claims the scenario needs.
#
#   TOKEN_SOURCE=real
#       Run the L2 private_key_jwt flow via the custodian: POST /token, which
#       signs the assertion AND performs the exchange at the auth server, then
#       returns the access token. scope + organization_reference come from the
#       REGISTERED CLIENT (not from here); CONTEXT_REF is passed to /token as RFC
#       9396 authorization_details so the issued token carries it as fhirContext.
#
# Claims via env:
#   SCOPE        e.g. "system/Task.c system/Task.u"   (mock only; real uses client defaults)
#   ORG_REF      e.g. ".../Organization/HospitalA"    (mock only; real fixed by client)
#   CONTEXT_REF  e.g. "ServiceRequest/sr-e2e"         (optional; both sources)
# =============================================================================
set -eu
TOKEN_SOURCE="${TOKEN_SOURCE:-mock}"
SCOPE="${SCOPE:-}"
ORG_REF="${ORG_REF:-}"
CONTEXT_REF="${CONTEXT_REF:-}"

extract_access_token() { sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'; }

if [ "$TOKEN_SOURCE" = "mock" ]; then
    MOCK_AUTH_URL="${MOCK_AUTH_URL:-http://localhost:9099}"
    fc=""
    [ -n "$CONTEXT_REF" ] && fc=",\"fhirContext\":[{\"reference\":\"${CONTEXT_REF}\"}]"
    body="{\"scope\":\"${SCOPE}\",\"organization_reference\":\"${ORG_REF}\"${fc}}"
    curl -sf -X POST -H "Content-Type: application/json" -d "$body" \
        "${MOCK_AUTH_URL}/token" | extract_access_token
    exit 0
fi

# --- real auth server (L2 private_key_jwt), brokered by the custodian ---
# The custodian owns the assertion signing AND the exchange: we just ask it for a
# token. CONTEXT_REF (if any) rides along as RFC 9396 authorization_details.
CUSTODIAN_URL="${CUSTODIAN_URL:-http://localhost:9087}"

if [ -n "$CONTEXT_REF" ]; then
    body="{\"authorization_details\":[{\"type\":\"umzh-connect-context\",\"identifier\":\"${CONTEXT_REF}\"}]}"
else
    body="{}"
fi

resp=$(curl -sf -X POST -H "Content-Type: application/json" -d "$body" "${CUSTODIAN_URL}/token") \
    || { echo "get-token: custodian /token at ${CUSTODIAN_URL} failed" >&2; exit 1; }
printf '%s' "$resp" | extract_access_token
