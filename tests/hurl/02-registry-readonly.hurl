# =============================================================================
# 02-registry-readonly — the registry exposes GET on the mCSD directory types
# only; every write, and every other resource type, is denied at the edge.
# =============================================================================

# Allowed: read the directory types.
GET {{registry_url}}/fhir/Organization
HTTP 200
[Asserts]
jsonpath "$.resourceType" == "Bundle"

GET {{registry_url}}/fhir/HealthcareService
HTTP 200
[Asserts]
jsonpath "$.resourceType" == "Bundle"

GET {{registry_url}}/fhir/Endpoint
HTTP 200
[Asserts]
jsonpath "$.resourceType" == "Bundle"

# Denied: writes to an allowed type (limit_except GET HEAD).
POST {{registry_url}}/fhir/Organization
Content-Type: application/fhir+json
{
  "resourceType": "Organization",
  "name": "Should Not Be Created"
}
HTTP 403

# Denied: a resource type outside the directory allowlist.
GET {{registry_url}}/fhir/Patient
HTTP 403

# Denied: the base endpoint (batch/transaction, $operations, …).
GET {{registry_url}}/fhir
HTTP 403
