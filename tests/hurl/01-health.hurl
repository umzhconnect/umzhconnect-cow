# =============================================================================
# 01-health — every service answers, no auth required.
# =============================================================================

# External gateway health probe.
GET {{gateway_url}}/healthz
HTTP 200

# Public JWK Set, proxied by the gateway to the key custodian.
GET {{gateway_url}}/jwks.json
HTTP 200
[Asserts]
jsonpath "$.keys" count > 0
jsonpath "$.keys[0].kty" == "RSA"

# Registry CapabilityStatement (public, read-only directory).
GET {{registry_url}}/fhir/metadata
HTTP 200
[Asserts]
jsonpath "$.resourceType" == "CapabilityStatement"

# Key custodian self-report.
GET {{custodian_url}}/healthz
HTTP 200
[Asserts]
jsonpath "$.kid" exists
jsonpath "$.client_id" exists

# OPA liveness.
GET {{opa_url}}/health
HTTP 200
