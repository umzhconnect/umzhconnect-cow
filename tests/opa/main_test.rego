# =============================================================================
# main_test.rego — exhaustive unit tests for the authorization rules in
# opa/policies/main.rego (package umzh.authz). Rules 1b/1d/4/4b call http.send to
# fetch Task / Consent / ServiceRequest from HAPI; each test mocks that built-in
# with `with http.send as <fn>` so the suite is fully hermetic (no stack).
#
#   opa test opa/policies tests/opa            # or tests/scripts/opa-test.sh
# =============================================================================
package umzh.authz_test

import rego.v1

fhir_base := "http://hapi/fhir/clinical-orders"

org_a := "https://reg.example/Organization/A"
org_x := "https://reg.example/Organization/X"

# --- http.send mocks (branch on the request URL) -----------------------------

# A Task whose requester and owner are both org_a.
mock_task_a(req) := {"status_code": 200, "body": {
	"requester": {"reference": org_a},
	"owner": {"reference": org_a},
}} if contains(req.url, "/Task/")

# A Task owned/requested by someone else (org_x).
mock_task_x(req) := {"status_code": 200, "body": {
	"requester": {"reference": org_x},
	"owner": {"reference": org_x},
}} if contains(req.url, "/Task/")

# ServiceRequest context: active Consent naming org_a as actor, SR → Patient/p1.
mock_sr_ok(req) := {"status_code": 200, "body": {"entry": [{"resource": {
	"status": "active",
	"provision": {"actor": [{"reference": {"reference": org_a}}]},
}}]}} if contains(req.url, "/Consent?data=")

mock_sr_ok(req) := {"status_code": 200, "body": {"subject": {"reference": "Patient/p1"}}} if {
	contains(req.url, "/ServiceRequest/")
}

# Same, but the Consent names a different actor (org_x).
mock_sr_wrong_actor(req) := {"status_code": 200, "body": {"entry": [{"resource": {
	"status": "active",
	"provision": {"actor": [{"reference": {"reference": org_x}}]},
}}]}} if contains(req.url, "/Consent?data=")

mock_sr_wrong_actor(req) := {"status_code": 200, "body": {"subject": {"reference": "Patient/p1"}}} if {
	contains(req.url, "/ServiceRequest/")
}

# Same actor, but the Consent expired in the past.
mock_sr_expired(req) := {"status_code": 200, "body": {"entry": [{"resource": {
	"status": "active",
	"provision": {
		"actor": [{"reference": {"reference": org_a}}],
		"period": {"end": "2000-01-01"},
	},
}}]}} if contains(req.url, "/Consent?data=")

mock_sr_expired(req) := {"status_code": 200, "body": {"subject": {"reference": "Patient/p1"}}} if {
	contains(req.url, "/ServiceRequest/")
}

# No Consent found for the context.
mock_sr_no_consent(req) := {"status_code": 200, "body": {"entry": []}} if contains(req.url, "/Consent?data=")

mock_sr_no_consent(req) := {"status_code": 200, "body": {"subject": {"reference": "Patient/p1"}}} if {
	contains(req.url, "/ServiceRequest/")
}

# Task context: active Consent (actor org_a) + a Task whose output references DocumentReference/d1.
mock_task_ctx_ok(req) := {"status_code": 200, "body": {"entry": [{"resource": {
	"status": "active",
	"provision": {"actor": [{"reference": {"reference": org_a}}]},
}}]}} if contains(req.url, "/Consent?data=")

mock_task_ctx_ok(req) := {"status_code": 200, "body": {"output": [{"valueReference": {"reference": "DocumentReference/d1"}}]}} if {
	contains(req.url, "/Task/")
}

# --- input builders ----------------------------------------------------------

req_in(method, rtype, rid, scope, org, ctx) := {
	"method": method,
	"resource_type": rtype,
	"resource_id": rid,
	"path": sprintf("/fhir/%s/%s", [rtype, rid]),
	"token": {"organization_reference": org, "scope": scope, "fhir_context": ctx},
	"fhir_base": fhir_base,
}

sr_ctx := [{"reference": "ServiceRequest/sr1"}]

task_ctx := [{"reference": "Task/t1"}]

# ============================================================================
# Rule 1a — Task search
# ============================================================================
test_1a_search_allowed if {
	data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/Task.s", org_a, [])
}

test_1a_denied_without_scope if {
	not data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/Patient.r", org_a, [])
}

test_1a_denied_empty_org if {
	not data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/Task.s", "", [])
}

# ============================================================================
# Rule 1b — Task read by id (requester must equal caller)
# ============================================================================
test_1b_read_allowed_requester_match if {
	data.umzh.authz.allow with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, [])
		with http.send as mock_task_a
}

test_1b_denied_requester_mismatch if {
	not data.umzh.authz.allow with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, [])
		with http.send as mock_task_x
}

# ============================================================================
# Optional backend auth — OPA attaches input.fhir_authorization to its FHIR
# fetches when set, and nothing when unset. Mocks assert on req.headers.
# ============================================================================

# Task-fetch mock that ALSO requires the configured Authorization header.
mock_task_a_auth(req) := {"status_code": 200, "body": {
	"requester": {"reference": org_a},
	"owner": {"reference": org_a},
}} if {
	contains(req.url, "/Task/")
	req.headers.Authorization == "Basic dGVzdDp0ZXN0"
}

# Task-fetch mock that requires NO Authorization header.
mock_task_a_noauth(req) := {"status_code": 200, "body": {
	"requester": {"reference": org_a},
	"owner": {"reference": org_a},
}} if {
	contains(req.url, "/Task/")
	not req.headers.Authorization
}

test_backend_auth_attached_when_set if {
	data.umzh.authz.allow with input as object.union(
		req_in("GET", "Task", "t1", "system/Task.r", org_a, []),
		{"fhir_authorization": "Basic dGVzdDp0ZXN0"},
	)
		with http.send as mock_task_a_auth
}

test_backend_auth_absent_when_unset if {
	data.umzh.authz.allow with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, [])
		with http.send as mock_task_a_noauth
}

# ============================================================================
# Rule 1c — Task create (scope only)
# ============================================================================
test_1c_create_allowed if {
	data.umzh.authz.allow with input as req_in("POST", "Task", "", "system/Task.c", org_a, [])
}

test_1c_denied_without_scope if {
	not data.umzh.authz.allow with input as req_in("POST", "Task", "", "system/Task.r", org_a, [])
}

# ============================================================================
# Rule 1d — Task update (owner must equal caller)
# ============================================================================
test_1d_patch_allowed_owner_match if {
	data.umzh.authz.allow with input as req_in("PATCH", "Task", "t1", "system/Task.u", org_a, [])
		with http.send as mock_task_a
}

test_1d_denied_owner_mismatch if {
	not data.umzh.authz.allow with input as req_in("PATCH", "Task", "t1", "system/Task.u", org_a, [])
		with http.send as mock_task_x
}

# ============================================================================
# Rule 2 / 3 — Questionnaire[Response]
# ============================================================================
test_2_questionnaire_response_create if {
	data.umzh.authz.allow with input as req_in("POST", "QuestionnaireResponse", "", "system/QuestionnaireResponse.c", org_a, [])
}

test_3_questionnaire_read if {
	data.umzh.authz.allow with input as req_in("GET", "Questionnaire", "q1", "system/Questionnaire.r", org_a, [])
}

# ============================================================================
# Rule 4 — ServiceRequest graph (consent + in-graph)
# ============================================================================
test_4_sr_read_allowed if {
	data.umzh.authz.allow with input as req_in("GET", "ServiceRequest", "sr1", "system/ServiceRequest.r", org_a, sr_ctx)
		with http.send as mock_sr_ok
}

test_4_referenced_patient_allowed if {
	data.umzh.authz.allow with input as req_in("GET", "Patient", "p1", "system/Patient.r", org_a, sr_ctx)
		with http.send as mock_sr_ok
}

test_4_denied_not_in_graph if {
	not data.umzh.authz.allow with input as req_in("GET", "Patient", "p999", "system/Patient.r", org_a, sr_ctx)
		with http.send as mock_sr_ok
}

test_4_denied_wrong_actor if {
	not data.umzh.authz.allow with input as req_in("GET", "ServiceRequest", "sr1", "system/ServiceRequest.r", org_a, sr_ctx)
		with http.send as mock_sr_wrong_actor
}

test_4_denied_expired_consent if {
	not data.umzh.authz.allow with input as req_in("GET", "ServiceRequest", "sr1", "system/ServiceRequest.r", org_a, sr_ctx)
		with http.send as mock_sr_expired
}

test_4_denied_no_consent if {
	not data.umzh.authz.allow with input as req_in("GET", "ServiceRequest", "sr1", "system/ServiceRequest.r", org_a, sr_ctx)
		with http.send as mock_sr_no_consent
}

test_4_denied_without_scope if {
	not data.umzh.authz.allow with input as req_in("GET", "ServiceRequest", "sr1", "system/Patient.r", org_a, sr_ctx)
		with http.send as mock_sr_ok
}

# ============================================================================
# Rule 4b — Task graph (placer reading Task output)
# ============================================================================
test_4b_task_output_read_allowed if {
	data.umzh.authz.allow with input as req_in("GET", "DocumentReference", "d1", "system/DocumentReference.r", org_a, task_ctx)
		with http.send as mock_task_ctx_ok
}

# ============================================================================
# Rule 5 — metadata (always)
# ============================================================================
test_5_metadata_allowed if {
	data.umzh.authz.allow with input as {"method": "GET", "path": "/fhir/metadata", "resource_type": "", "resource_id": "", "token": {"organization_reference": "", "scope": "", "fhir_context": []}, "fhir_base": fhir_base}
}

# ============================================================================
# Rule 6 — directory reads
# ============================================================================
test_6_organization_read_allowed if {
	data.umzh.authz.allow with input as req_in("GET", "Organization", "o1", "system/Organization.r", org_a, [])
}

test_6_denied_without_scope if {
	not data.umzh.authz.allow with input as req_in("GET", "Organization", "o1", "system/Patient.r", org_a, [])
}

# ============================================================================
# Scope syntax — combined SMART v2 letters are honored; wildcards are NOT
# ============================================================================

# One combined scope (system/Task.crus) satisfies every single-action Task check.
test_combined_scope_task_search if {
	data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/Task.crus", org_a, [])
}

test_combined_scope_task_create if {
	data.umzh.authz.allow with input as req_in("POST", "Task", "", "system/Task.crus", org_a, [])
}

# Wildcard resource scopes are NOT supported: `system/*.r` must not grant a read
# on a concrete type (has_smart_scope matches the resource literally).
test_wildcard_scope_denied if {
	not data.umzh.authz.allow with input as req_in("GET", "Organization", "o1", "system/*.r", org_a, [])
}

test_wildcard_scope_denied_task if {
	not data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/*.crus", org_a, [])
}

# ============================================================================
# Cross-cutting — a resource read with no context/consent is denied
# ============================================================================
test_uncontexted_read_denied if {
	not data.umzh.authz.allow with input as req_in("GET", "Patient", "p1", "system/Patient.r", org_a, [])
}
