# =============================================================================
# fulfiller.hurl — this node acting AS THE FULFILLER: its gateway serves Task
# create (by a placer) and Task update (by the fulfiller owner). Self-seeding —
# it creates the Tasks it exercises; the runner's teardown sweeps them by
# identifier (urn:umzhc:test|e2e).
#
# {{token}} is minted by the runner with scope system/Task.{c,r,s,u} and
# organization_reference = {{our_org}} (the Task owner). requester is set to the
# same org so the requester-injected list and read-by-id (Rule 1b) match.
# =============================================================================

# Auth boundary: creating a Task requires a bearer.
POST {{gateway_url}}/fhir/Task
Content-Type: application/fhir+json
{ "resourceType": "Task", "status": "requested", "intent": "order" }
HTTP 401

# Create a Task (OPA Rule 1c: system/Task.c).
POST {{gateway_url}}/fhir/Task
Authorization: Bearer {{token}}
Content-Type: application/fhir+json
{
  "resourceType": "Task",
  "status": "requested",
  "intent": "order",
  "identifier": [{ "system": "urn:umzhc:test", "value": "e2e" }],
  "requester": { "reference": "{{our_org}}" },
  "owner": { "reference": "{{our_org}}" }
}
HTTP 201
[Captures]
task_id: jsonpath "$.id"
[Asserts]
jsonpath "$.resourceType" == "Task"

# List — requester-injected to our org; the new Task is present (Rule 1a).
# Cache-Control: no-cache bypasses HAPI's search-result cache
# (reuse_cached_search_results_millis, default 60s) so the just-created Task is
# visible immediately rather than served from a stale cached result set.
GET {{gateway_url}}/fhir/Task
Authorization: Bearer {{token}}
Cache-Control: no-cache
HTTP 200
[Asserts]
jsonpath "$.resourceType" == "Bundle"
jsonpath "$.entry[*].resource.id" includes "{{task_id}}"

# Read by id — Rule 1b (requester == our org).
GET {{gateway_url}}/fhir/Task/{{task_id}}
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.id" == "{{task_id}}"

# Update a patchable field — Rule 1d (Task.u AND owner == our org).
# `add` (not `replace`): businessStatus isn't set at create, and JSON-Patch
# replace requires an existing path (HAPI-1272). `add` sets-or-replaces.
PATCH {{gateway_url}}/fhir/Task/{{task_id}}
Authorization: Bearer {{token}}
Content-Type: application/json-patch+json
[
  { "op": "add", "path": "/businessStatus", "value": { "text": "received" } }
]
HTTP 200
[Asserts]
jsonpath "$.businessStatus.text" == "received"

# --- Negatives (gateway path) ------------------------------------------------

# A non-patchable field → capability-guard 400 (before OPA / upstream).
PATCH {{gateway_url}}/fhir/Task/{{task_id}}
Authorization: Bearer {{token}}
Content-Type: application/json-patch+json
[
  { "op": "replace", "path": "/status", "value": "completed" }
]
HTTP 400
[Asserts]
jsonpath "$.resourceType" == "OperationOutcome"

# A Task owned by someone else → PATCH as us fails the owner check (Rule 1d, 403).
POST {{gateway_url}}/fhir/Task
Authorization: Bearer {{token}}
Content-Type: application/fhir+json
{
  "resourceType": "Task",
  "status": "requested",
  "intent": "order",
  "identifier": [{ "system": "urn:umzhc:test", "value": "e2e" }],
  "requester": { "reference": "{{our_org}}" },
  "owner": { "reference": "http://localhost:9084/fhir/Organization/SomeoneElse" }
}
HTTP 201
[Captures]
other_task_id: jsonpath "$.id"

PATCH {{gateway_url}}/fhir/Task/{{other_task_id}}
Authorization: Bearer {{token}}
Content-Type: application/json-patch+json
[
  { "op": "add", "path": "/businessStatus", "value": { "text": "received" } }
]
HTTP 403
