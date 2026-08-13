# =============================================================================
# placer.hurl — this node acting AS THE PLACER: its gateway serves authorized
# reads of a ServiceRequest and the resources in its graph, to a partner
# (fulfiller) carrying a fhirContext token. Consent/fhirContext-gated (OPA Rule 4).
#
# {{token}} is minted by the runner (mock or real source) with
#   scope: system/ServiceRequest.r system/Patient.r
#   fhirContext: ServiceRequest/{{sr_id}}
#   organization_reference: the org the seeded Consent names as actor.
# Fixtures seeded by tests/scripts/seed.sh up. Consent-actor-mismatch and other
# pure-policy denials live in the OPA unit tests (tests/opa/).
# =============================================================================

# Auth boundary: this route requires a bearer.
GET {{gateway_url}}/fhir/ServiceRequest/{{sr_id}}
HTTP 401

# Authorized ServiceRequest search by _id → 200 Bundle.
# Cache-Control: no-cache bypasses HAPI's search-result cache so the freshly
# (re)seeded ServiceRequest is read live, not from a stale cached result set.
GET {{gateway_url}}/fhir/ServiceRequest?_id={{sr_id}}
Authorization: Bearer {{token}}
Cache-Control: no-cache
HTTP 200
[Asserts]
jsonpath "$.resourceType" == "Bundle"
jsonpath "$.entry[0].resource.resourceType" == "ServiceRequest"
jsonpath "$.entry[0].resource.id" == "{{sr_id}}"

# _include pulls the referenced Patient (in the SR graph) into the bundle.
GET {{gateway_url}}/fhir/ServiceRequest?_id={{sr_id}}&_include=ServiceRequest:subject
Authorization: Bearer {{token}}
Cache-Control: no-cache
HTTP 200
[Asserts]
jsonpath "$.entry[*].resource.resourceType" includes "Patient"

# Read the ServiceRequest by id.
GET {{gateway_url}}/fhir/ServiceRequest/{{sr_id}}
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{sr_id}}"

# Read a referenced resource (Patient) — permitted because it is in the graph.
GET {{gateway_url}}/fhir/Patient/{{pat_id}}
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.resourceType" == "Patient"
jsonpath "$.id" == "{{pat_id}}"

# --- Negatives (gateway path) ------------------------------------------------

# ServiceRequest search without _id → capability-guard 400.
GET {{gateway_url}}/fhir/ServiceRequest
Authorization: Bearer {{token}}
HTTP 400
[Asserts]
jsonpath "$.resourceType" == "OperationOutcome"

# A resource that is NOT in the SR graph → OPA denies (403), end to end.
GET {{gateway_url}}/fhir/Patient/not-in-graph
Authorization: Bearer {{token}}
HTTP 403
