# =============================================================================
# placer.hurl — this node acting AS THE PLACER: its gateway serves authorized
# reads of a ServiceRequest and the resources in its graph, to a partner
# (fulfiller) carrying a context token. Consent- and context-gated (OPA Rule 4).
#
# {{token}} is minted by the runner (mock or real source) with
#   scope: system/ServiceRequest.rs system/Patient.rs system/PractitionerRole.rs
#   authorization_details: the context ServiceRequest/{{sr_id}}
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

# An allowlisted _include:iterate value passes the capability-guard: the SR's
# requester (PractitionerRole) is included, and iterating
# PractitionerRole:practitioner pulls in the referenced Practitioner too.
GET {{gateway_url}}/fhir/ServiceRequest?_id={{sr_id}}&_include=ServiceRequest:requester&_include:iterate=PractitionerRole:practitioner
Authorization: Bearer {{token}}
Cache-Control: no-cache
HTTP 200
[Asserts]
jsonpath "$.entry[*].resource.resourceType" includes "PractitionerRole"
jsonpath "$.entry[*].resource.resourceType" includes "Practitioner"

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

# Search a read-only type by _id — same graph check as the read above.
GET {{gateway_url}}/fhir/Patient?_id={{pat_id}}
Authorization: Bearer {{token}}
Cache-Control: no-cache
HTTP 200
[Asserts]
jsonpath "$.resourceType" == "Bundle"
jsonpath "$.entry[0].resource.id" == "{{pat_id}}"

# A second-level resource through the first-level search: the SR's requester
# (PractitionerRole, in the graph) with its Practitioner.
GET {{gateway_url}}/fhir/PractitionerRole?_id=prrole-e2e&_include=PractitionerRole:practitioner
Authorization: Bearer {{token}}
Cache-Control: no-cache
HTTP 200
[Asserts]
jsonpath "$.entry[*].resource.resourceType" includes "PractitionerRole"
jsonpath "$.entry[*].resource.resourceType" includes "Practitioner"

# --- Negatives (gateway path) ------------------------------------------------

# ServiceRequest search without _id → capability-guard 400.
GET {{gateway_url}}/fhir/ServiceRequest
Authorization: Bearer {{token}}
HTTP 400
[Asserts]
jsonpath "$.resourceType" == "OperationOutcome"

# _include:iterate with a value that is not allowlisted → capability-guard 400.
GET {{gateway_url}}/fhir/ServiceRequest?_id={{sr_id}}&_include:iterate=Observation:subject
Authorization: Bearer {{token}}
HTTP 400
[Asserts]
jsonpath "$.resourceType" == "OperationOutcome"
jsonpath "$.issue[0].diagnostics" contains "unsupported _include:iterate value: Observation:subject"

# _include:recurse (the older name for :iterate, still honoured by HAPI) is
# rejected as a modifier, so it cannot get around the iterate allowlist.
GET {{gateway_url}}/fhir/ServiceRequest?_id={{sr_id}}&_include=ServiceRequest:requester&_include:recurse=PractitionerRole:practitioner
Authorization: Bearer {{token}}
HTTP 400
[Asserts]
jsonpath "$.issue[0].diagnostics" contains "modifier not supported: _include:recurse"

# A direct _include value may not iterate: iterating re-applies it to every
# ServiceRequest the result set picks up (e.g. via supportingInfo), which can
# walk out of the SR graph.
GET {{gateway_url}}/fhir/ServiceRequest?_id={{sr_id}}&_include:iterate=ServiceRequest:subject
Authorization: Bearer {{token}}
HTTP 400
[Asserts]
jsonpath "$.issue[0].diagnostics" contains "unsupported _include:iterate value: ServiceRequest:subject"

# Read-only search without _id → capability-guard 400.
GET {{gateway_url}}/fhir/Patient
Authorization: Bearer {{token}}
HTTP 400
[Asserts]
jsonpath "$.issue[0].diagnostics" contains "missing required search parameter: _id"

# An _include value that is not allowlisted → capability-guard 400.
GET {{gateway_url}}/fhir/Patient?_id={{pat_id}}&_include=Patient:general-practitioner
Authorization: Bearer {{token}}
HTTP 400
[Asserts]
jsonpath "$.issue[0].diagnostics" contains "unsupported _include value: Patient:general-practitioner"

# A resource that is NOT in the SR graph → OPA denies (403), end to end.
GET {{gateway_url}}/fhir/Patient/not-in-graph
Authorization: Bearer {{token}}
HTTP 403

# The same through search: an _id outside the graph is denied, not an empty Bundle.
GET {{gateway_url}}/fhir/Patient?_id=not-in-graph
Authorization: Bearer {{token}}
HTTP 403
