# =============================================================================
# fulfiller.hurl — this node acting AS THE FULFILLER: its gateway serves Task
# create and Task update by a placer. Self-seeding — it creates the Tasks it
# exercises; the runner's teardown sweeps them by identifier (urn:umzhc:test|e2e).
#
# {{token}} is minted by the runner with scope system/Task.{c,r,s,u} and
# system/Questionnaire.rs, and organization_reference = {{our_org}}, so it acts as
# the placer named in Task.requester. What the fulfiller does to its own Tasks
# goes straight to {{proxy_url}}: those writes don't use the gateway.
# =============================================================================

# Auth boundary: creating a Task requires a bearer.
POST {{gateway_url}}/fhir/Task
Content-Type: application/fhir+json
{ "resourceType": "Task", "status": "requested", "intent": "order" }
HTTP 401

# Create a Task (OPA Rule 1c: system/Task.c AND requester == our org).
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

# Delta polling — _lastUpdated passes the guard.
GET {{gateway_url}}/fhir/Task?_lastUpdated=gt2000-01-01
Authorization: Bearer {{token}}
Cache-Control: no-cache
HTTP 200
[Asserts]
jsonpath "$.entry[*].resource.id" includes "{{task_id}}"

# Read by id — Rule 1b (requester == our org).
GET {{gateway_url}}/fhir/Task/{{task_id}}
Authorization: Bearer {{token}}
HTTP 200
[Captures]
version: jsonpath "$.meta.versionId"
[Asserts]
jsonpath "$.id" == "{{task_id}}"

# --- Cancel (Rule 1d) ---------------------------------------------------------

# A stale If-Match → 412.
PUT {{gateway_url}}/fhir/Task/{{task_id}}
Authorization: Bearer {{token}}
If-Match: W/"99"
Content-Type: application/fhir+json
{
  "resourceType": "Task",
  "id": "{{task_id}}",
  "status": "cancelled",
  "intent": "order",
  "identifier": [{ "system": "urn:umzhc:test", "value": "e2e" }],
  "requester": { "reference": "{{our_org}}" },
  "owner": { "reference": "{{our_org}}" }
}
HTTP 412

# The cancel itself, with a reason.
PUT {{gateway_url}}/fhir/Task/{{task_id}}
Authorization: Bearer {{token}}
If-Match: W/"{{version}}"
Content-Type: application/fhir+json
{
  "resourceType": "Task",
  "id": "{{task_id}}",
  "status": "cancelled",
  "statusReason": { "text": "entered in error" },
  "intent": "order",
  "identifier": [{ "system": "urn:umzhc:test", "value": "e2e" }],
  "requester": { "reference": "{{our_org}}" },
  "owner": { "reference": "{{our_org}}" }
}
HTTP 200
[Asserts]
jsonpath "$.status" == "cancelled"

# --- Answer a request for information (Rule 1d) -------------------------------

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
asked_task_id: jsonpath "$.id"

# The fulfiller starts work and asks for information.
PUT {{proxy_url}}/fhir/Task/{{asked_task_id}}
Content-Type: application/fhir+json
{
  "resourceType": "Task",
  "id": "{{asked_task_id}}",
  "status": "in-progress",
  "businessStatus": { "coding": [{ "system": "http://hl7.org/fhir/uv/cow/CodeSystem/temp", "code": "awaiting-information" }] },
  "intent": "order",
  "identifier": [{ "system": "urn:umzhc:test", "value": "e2e" }],
  "requester": { "reference": "{{our_org}}" },
  "owner": { "reference": "{{our_org}}" },
  "output": [{ "type": { "text": "questions" }, "valueCanonical": "http://example.org/Questionnaire/e2e" }]
}
HTTP 200
[Captures]
asked_version: jsonpath "$.meta.versionId"

# The answer: input added, businessStatus removed.
PUT {{gateway_url}}/fhir/Task/{{asked_task_id}}
Authorization: Bearer {{token}}
If-Match: W/"{{asked_version}}"
Content-Type: application/fhir+json
{
  "resourceType": "Task",
  "id": "{{asked_task_id}}",
  "status": "in-progress",
  "intent": "order",
  "identifier": [{ "system": "urn:umzhc:test", "value": "e2e" }],
  "requester": { "reference": "{{our_org}}" },
  "owner": { "reference": "{{our_org}}" },
  "output": [{ "type": { "text": "questions" }, "valueCanonical": "http://example.org/Questionnaire/e2e" }],
  "input": [{ "type": { "text": "answers" }, "valueReference": { "reference": "http://example.org/fhir/QuestionnaireResponse/e2e" } }]
}
HTTP 200
[Asserts]
jsonpath "$.input" count == 1
jsonpath "$.businessStatus" not exists

# --- Questionnaire search (OPA Rule 3) ----------------------------------------

GET {{gateway_url}}/fhir/Questionnaire?url=http://example.org/Questionnaire/none
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.resourceType" == "Bundle"

# --- Negatives (gateway path) ------------------------------------------------

# PATCH is gone: no route.
PATCH {{gateway_url}}/fhir/Task/{{task_id}}
Authorization: Bearer {{token}}
Content-Type: application/json-patch+json
[
  { "op": "add", "path": "/businessStatus", "value": { "text": "received" } }
]
HTTP 404

# owner is no longer a Task search parameter → capability-guard 400.
GET {{gateway_url}}/fhir/Task?owner={{our_org}}
Authorization: Bearer {{token}}
HTTP 400
[Asserts]
jsonpath "$.issue[0].diagnostics" contains "unsupported search parameter: owner"

# Task outputs are context-gated: this token has no Task context, so OPA denies
# the _include (403) before HAPI is asked.
GET {{gateway_url}}/fhir/Task?_id={{task_id}}&_include=Task:output-value-reference
Authorization: Bearer {{token}}
HTTP 403

# A Task someone else requested. Conditional create would return it → 403.
POST {{proxy_url}}/fhir/Task
Content-Type: application/fhir+json
{
  "resourceType": "Task",
  "status": "requested",
  "intent": "order",
  "identifier": [{ "system": "urn:umzhc:test", "value": "e2e" }],
  "requester": { "reference": "http://localhost:9084/fhir/Organization/SomeoneElse" },
  "owner": { "reference": "{{our_org}}" }
}
HTTP 201
[Captures]
other_task_id: jsonpath "$.id"

POST {{gateway_url}}/fhir/Task
Authorization: Bearer {{token}}
If-None-Exist: _id={{other_task_id}}
Content-Type: application/fhir+json
{
  "resourceType": "Task",
  "status": "requested",
  "intent": "order",
  "identifier": [{ "system": "urn:umzhc:test", "value": "e2e" }],
  "requester": { "reference": "{{our_org}}" },
  "owner": { "reference": "{{our_org}}" }
}
HTTP 403

# PUT doesn't create: an unknown id → 403.
PUT {{gateway_url}}/fhir/Task/not-a-task
Authorization: Bearer {{token}}
If-Match: W/"1"
Content-Type: application/fhir+json
{
  "resourceType": "Task",
  "id": "not-a-task",
  "status": "cancelled",
  "intent": "order",
  "requester": { "reference": "{{our_org}}" },
  "owner": { "reference": "{{our_org}}" }
}
HTTP 403
