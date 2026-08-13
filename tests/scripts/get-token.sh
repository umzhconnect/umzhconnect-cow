#!/bin/sh
# =============================================================================
# get-token.sh — print one access token for a test scenario. Two sources, chosen
# by TOKEN_SOURCE so the same tests run against the mock OR a real auth server:
#
#   TOKEN_SOURCE=mock (default)
#       POST the mock issuer's /token with the EXACT claims the scenario needs.
#
#   TOKEN_SOURCE=real
#       Run the L2 private_key_jwt flow: custodian /sign → exchange at the auth
#       server. scope + organization_reference come from the REGISTERED CLIENT
#       (not from here); CONTEXT_REF is sent as RFC 9396 authorization_details so
#       the issued token carries it as fhirContext.
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

# --- real auth server (L2 private_key_jwt) ---
CUSTODIAN_URL="${CUSTODIAN_URL:-http://localhost:9087}"
KC_URL="${KC_URL:-http://localhost:8180}"
KC_REALM="${KC_REALM:-umzh-connect}"
CLIENT_ID="${CLIENT_ID:-fulfiller-client-l2}"
TOKEN_URL="${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token"
ASSERTION_TYPE="urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"

sign_resp=$(curl -sf -X POST -H "Content-Type: application/json" \
    -d "{\"audience\":\"${TOKEN_URL}\"}" "${CUSTODIAN_URL}/sign")
assertion=$(printf '%s' "$sign_resp" | sed -n 's/.*"assertion"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
[ -z "$assertion" ] && { echo "get-token: custodian /sign at ${CUSTODIAN_URL} failed" >&2; exit 1; }

body="grant_type=client_credentials&client_id=${CLIENT_ID}"
body="${body}&client_assertion_type=${ASSERTION_TYPE}&client_assertion=${assertion}"
if [ -n "$CONTEXT_REF" ]; then
    ad="[{\"type\":\"umzh-connect-context\",\"identifier\":\"${CONTEXT_REF}\"}]"
    ad_enc=$(printf '%s' "$ad" | sed 's/%/%25/g;s/ /%20/g;s/"/%22/g;s/{/%7B/g;s/}/%7D/g;s/\[/%5B/g;s/\]/%5D/g;s/:/%3A/g;s/,/%2C/g;s|/|%2F|g')
    body="${body}&authorization_details=${ad_enc}"
fi

curl -sf -H "Content-Type: application/x-www-form-urlencoded" -d "$body" \
    "$TOKEN_URL" | extract_access_token
