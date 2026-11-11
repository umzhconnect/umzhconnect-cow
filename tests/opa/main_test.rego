# =============================================================================
# main_test.rego — exhaustive unit tests for the authorization rules in
# opa/policies/main.rego (package umzh.authz). Rules 1b/1d/4/4b call http.send to
# fetch Task / Consent / ServiceRequest from HAPI; each test mocks that built-in
# with `with http.send as <fn>` so the suite is fully hermetic (no stack).
#
#   opa test opa/policies tests/opa            # or tests/scripts/opa-test.sh
#
# tests/opa/data.json stands in for opa-config.json: it sets data.config.fhir_base.
# =============================================================================
package umzh.authz_test

import rego.v1

org_a := "https://reg.example/Organization/A"
org_x := "https://reg.example/Organization/X"

active_sr := {"status": "active", "subject": {"reference": "Patient/p1"}}

consent_ok := {"status_code": 200, "body": {"entry": [{"resource": {
	"status": "active",
	"provision": {"actor": [{"reference": {"reference": org_a}}]},
}}]}}

# --- http.send mocks (branch on the request URL) -----------------------------

# A valid Consent, plus <body> for any URL containing <path>.
mock_ctx(req, _, _) := consent_ok if contains(req.url, "/Consent?data=")

mock_ctx(req, path, body) := {"status_code": 200, "body": body} if contains(req.url, path)

# A Task requested by org_a.
mock_task_a(req) := {"status_code": 200, "body": {"requester": {"reference": org_a}}} if {
	contains(req.url, "/Task/")
}

# A Task requested by someone else (org_x).
mock_task_x(req) := {"status_code": 200, "body": {"requester": {"reference": org_x}}} if {
	contains(req.url, "/Task/")
}

# ServiceRequest context: active Consent naming org_a as actor, SR → Patient/p1.
mock_sr_ok(req) := {"status_code": 200, "body": {"entry": [{"resource": {
	"status": "active",
	"provision": {"actor": [{"reference": {"reference": org_a}}]},
}}]}} if contains(req.url, "/Consent?data=")

mock_sr_ok(req) := {"status_code": 200, "body": active_sr} if {
	contains(req.url, "/ServiceRequest/")
}

# Same, but the Consent names a different actor (org_x).
mock_sr_wrong_actor(req) := {"status_code": 200, "body": {"entry": [{"resource": {
	"status": "active",
	"provision": {"actor": [{"reference": {"reference": org_x}}]},
}}]}} if contains(req.url, "/Consent?data=")

mock_sr_wrong_actor(req) := {"status_code": 200, "body": active_sr} if {
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

mock_sr_expired(req) := {"status_code": 200, "body": active_sr} if {
	contains(req.url, "/ServiceRequest/")
}

# No Consent found for the context.
mock_sr_no_consent(req) := {"status_code": 200, "body": {"entry": []}} if contains(req.url, "/Consent?data=")

mock_sr_no_consent(req) := {"status_code": 200, "body": active_sr} if {
	contains(req.url, "/ServiceRequest/")
}

# Valid Consent, but the ServiceRequest was revoked.
mock_sr_revoked(req) := mock_ctx(req, "/ServiceRequest/", object.union(active_sr, {"status": "revoked"}))

# Task context: a Task requested by org_a whose output references DocumentReference/d1.
mock_task_ctx_ok(req) := {"status_code": 200, "body": {
	"requester": {"reference": org_a},
	"output": [{"valueReference": {"reference": "DocumentReference/d1"}}],
}} if contains(req.url, "/Task/")

# Same Task, requested by someone else.
mock_task_ctx_other(req) := {"status_code": 200, "body": {
	"requester": {"reference": org_x},
	"output": [{"valueReference": {"reference": "DocumentReference/d1"}}],
}} if contains(req.url, "/Task/")

# Contexts whose graph holds a reference ending in Patient/, which a blank _id would match.
mock_sr_blank_ref(req) := mock_ctx(req, "/ServiceRequest/", {"status": "active", "subject": {"reference": "Patient/"}})

mock_task_blank_ref(req) := mock_stored(req, {
	"requester": {"reference": org_a},
	"output": [{"valueReference": {"reference": "Patient/"}}],
})

# Task context whose Task lists Patient/p9 in input only: Task.input is not in the graph.
mock_task_ctx_input(req) := mock_stored(req, {
	"requester": {"reference": org_a},
	"input": [{"valueReference": {"reference": "Patient/p9"}}],
})

# ServiceRequest context + a QuestionnaireResponse with the given basedOn.
mock_qr(req, _) := consent_ok if contains(req.url, "/Consent?data=")

mock_qr(req, _) := {"status_code": 200, "body": active_sr} if {
	contains(req.url, "/ServiceRequest/")
}

mock_qr(req, based_on) := {"status_code": 200, "body": {"basedOn": [{"reference": based_on}]}} if {
	contains(req.url, "/QuestionnaireResponse/")
}

mock_qr_relative(req) := mock_qr(req, "ServiceRequest/sr1")

mock_qr_other_root(req) := mock_qr(req, "ServiceRequest/sr2")

mock_qr_other_server(req) := mock_qr(req, "https://other.example/fhir/ServiceRequest/sr1")

# The QuestionnaireResponse is listed in supportingInfo and has no basedOn.
mock_qr_forward(req) := consent_ok if contains(req.url, "/Consent?data=")

mock_qr_forward(req) := {"status_code": 200, "body": {
	"status": "active",
	"supportingInfo": [{"reference": "QuestionnaireResponse/qr1"}],
}} if contains(req.url, "/ServiceRequest/")

mock_qr_forward(req) := {"status_code": 200, "body": {}} if contains(req.url, "/QuestionnaireResponse/")

# --- Task writes -------------------------------------------------------------

# The Task as the Placer creates it, and as stored at version 3.
new_task := {
	"resourceType": "Task",
	"status": "requested",
	"intent": "order",
	"requester": {"reference": org_a},
	"focus": {"reference": "ServiceRequest/sr1"},
}

stored_task := object.union(new_task, {"id": "t1", "meta": {"versionId": "3"}})

cancelled_task := object.union(stored_task, {"status": "cancelled"})

# The stored Task once the Fulfiller asks for information, and the Placer's answer.
awaiting_task := object.union(stored_task, {
	"status": "in-progress",
	"businessStatus": {"coding": [{"code": "awaiting-information"}]},
	"output": [{"valueCanonical": "Questionnaire/q1"}],
})

answered_task := object.union(object.remove(awaiting_task, ["businessStatus"]), {"input": [{"valueString": "new"}]})

mock_stored(req, task) := {"status_code": 200, "body": task} if contains(req.url, "/Task/t1")

mock_requested(req) := mock_stored(req, stored_task)

mock_accepted(req) := mock_stored(req, object.union(stored_task, {"status": "accepted"}))

mock_in_progress(req) := mock_stored(req, object.union(stored_task, {"status": "in-progress"}))

mock_has_reason(req) := mock_stored(req, object.union(stored_task, {"statusReason": {"text": "old"}}))

mock_awaiting(req) := mock_stored(req, awaiting_task)

mock_awaiting_with_input(req) := mock_stored(req, object.union(awaiting_task, {"input": [{"valueString": "first"}, {"valueString": "second"}]}))

mock_other_business_status(req) := mock_stored(req, object.union(awaiting_task, {"businessStatus": {"coding": [{"code": "other"}]}}))

mock_other_requester(req) := mock_stored(req, object.union(stored_task, {"requester": {"reference": org_x}}))

mock_not_found(_) := {"status_code": 404, "body": {}}

# --- input builders ----------------------------------------------------------

# A read of <rtype>/<rid>, or with rid "" a search of <rtype>: the path says which.
req_in(method, rtype, rid, scope, org, ctx) := {
	"method": method,
	"path": type_path(rtype, rid),
	"query_params": [],
	"organization_reference": org,
	"scope": scope,
	"context": ctx,
}

type_path(rtype, "") := sprintf("/fhir/%s", [rtype])

type_path(rtype, rid) := sprintf("/fhir/%s/%s", [rtype, rid]) if rid != ""

# The query parameters of a search: _id when rid isn't "", then the extras.
search_params(rid, extra) := array.concat([{"_id": rid} | rid != ""], extra)

# GET /fhir/Task?_id=<rid>&_include=..., or without _id when rid is "".
task_include_in(rid, includes, ctx) := object.union(req_in("GET", "Task", rid, "system/Task.rs", org_a, ctx), {
	"path": "/fhir/Task",
	"query_params": search_params(rid, [{"_include": value} | some value in includes]),
})

# GET /fhir/<rtype>?_id=<rid>.
search_in(rtype, rid, scope, ctx) := object.union(req_in("GET", rtype, rid, scope, org_a, ctx), {
	"path": sprintf("/fhir/%s", [rtype]),
	"query_params": search_params(rid, []),
})

# A Task create with the given body.
create_in(body) := object.union(req_in("POST", "Task", "", "system/Task.c", org_a, ""), {"body": body})

# An update of Task/t1 with the given body, naming version 3.
update_in(body) := object.union(req_in("PUT", "Task", "t1", "system/Task.u", org_a, ""), {
	"body": body,
	"header_if_match": `W/"3"`,
})

sr_ctx := "ServiceRequest/sr1"

task_ctx := "Task/t1"

# ============================================================================
# Rule 1a — Task search
# ============================================================================
test_1a_search_allowed if {
	data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/Task.s", org_a, "")
}

test_1a_denied_without_scope if {
	not data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/Patient.r", org_a, "")
}

test_1a_denied_empty_org if {
	not data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/Task.s", "", "")
}

# _include needs _id, even a value that needs no context.
test_1a_include_denied_without_id if {
	every includes in [["Task:output-value-canonical"], ["DiagnosticReport:result"]] {
		not data.umzh.authz.allow with input as task_include_in("", includes, "")
	}
}

# Without _id there is no Task to bind a context to, even if the token has one.
test_1a_output_include_denied if {
	not data.umzh.authz.allow with input as task_include_in("", ["Task:output-value-reference"], task_ctx)
		with http.send as mock_task_a
}

test_1a_denied_when_any_include_needs_context if {
	not data.umzh.authz.allow with input as task_include_in("", ["Task:output-value-canonical", "Task:output-value-reference"], "")
}

# ============================================================================
# Rule 1b — Task read by id (requester must equal caller)
# ============================================================================
test_1b_read_allowed_requester_match if {
	data.umzh.authz.allow with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, "")
		with http.send as mock_task_a
}

test_1b_denied_requester_mismatch if {
	not data.umzh.authz.allow with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, "")
		with http.send as mock_task_x
}

# GET /Task?_id=t1 with an _include — context-gated results need a Task/t1 context.
test_1b_output_include_allowed_with_context if {
	data.umzh.authz.allow with input as task_include_in("t1", ["Task:output-value-reference"], task_ctx)
		with http.send as mock_task_a
}

test_1b_output_include_denied_without_context if {
	not data.umzh.authz.allow with input as task_include_in("t1", ["Task:output-value-reference"], "")
		with http.send as mock_task_a
}

test_1b_output_include_denied_for_other_task_context if {
	not data.umzh.authz.allow with input as task_include_in("t1", ["Task:output-value-reference"], "Task/t2")
		with http.send as mock_task_a
}

# Questionnaires are not context-gated: with _id, this _include needs no context.
test_1b_canonical_include_allowed_without_context if {
	data.umzh.authz.allow with input as task_include_in("t1", ["Task:output-value-canonical"], "")
		with http.send as mock_task_a
}

# An _id is a search parameter: a read by id may not include, even with the context.
test_1b_include_denied_on_read if {
	not data.umzh.authz.allow with input as object.union(
		task_include_in("t1", ["Task:output-value-reference"], task_ctx),
		{"path": "/fhir/Task/t1"},
	)
		with http.send as mock_task_a
}

# The _id rule holds for every type, not only Task.
test_3_include_denied_without_id if {
	not data.umzh.authz.allow with input as object.union(
		req_in("GET", "Questionnaire", "", "system/Questionnaire.s", org_a, ""),
		{"query_params": [{"_include": "Questionnaire:x"}]},
	)
}

# ============================================================================
# Backend configuration — fhir_base and the optional backend credential come
# from OPA's own data document and environment, never from the input.
# ============================================================================

# Default: no FHIR_BASE env → fhir_base comes from the opa-config.json data doc.
test_fhir_base_from_data_config if {
	data.umzh.authz.fhir_base == "http://cfg/fhir/clinical-orders" with opa.runtime as {"env": {}}
		with data.config as {"fhir_base": "http://cfg/fhir/clinical-orders"}
}

# A non-empty FHIR_BASE env overrides the data document (external-backend case).
test_fhir_base_env_override_wins if {
	data.umzh.authz.fhir_base == "https://external/fhir" with opa.runtime as {"env": {"FHIR_BASE": "https://external/fhir"}}
		with data.config as {"fhir_base": "http://cfg/fhir/clinical-orders"}
}

# An empty FHIR_BASE env is ignored → falls back to the data document.
test_fhir_base_empty_env_falls_back if {
	data.umzh.authz.fhir_base == "http://cfg/fhir/clinical-orders" with opa.runtime as {"env": {"FHIR_BASE": ""}}
		with data.config as {"fhir_base": "http://cfg/fhir/clinical-orders"}
}

# A caller can't choose the FHIR server: input.fhir_base is ignored.
test_input_fhir_base_ignored if {
	data.umzh.authz.allow with input as object.union(
		req_in("GET", "Task", "t1", "system/Task.r", org_a, ""),
		{"fhir_base": "https://rogue.example/fhir"},
	)
		with http.send as mock_task_from_config
}

mock_task_from_config(req) := {"status_code": 200, "body": {"requester": {"reference": org_a}}} if {
	startswith(req.url, "http://hapi/fhir/clinical-orders/Task/")
}

# No FHIR server configured → nothing is allowed, not even a rule that fetches nothing.
test_denied_without_fhir_base if {
	not data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/Task.s", org_a, "")
		with opa.runtime as {"env": {}}
		with data.config as {}
}

# The optional backend credential. Mocks assert on req.headers.

# Task-fetch mock that ALSO requires the configured Authorization header.
mock_task_a_auth(req) := {"status_code": 200, "body": {"requester": {"reference": org_a}}} if {
	contains(req.url, "/Task/")
	req.headers.Authorization == "Basic dGVzdDp0ZXN0"
}

# Task-fetch mock that requires NO Authorization header.
mock_task_a_noauth(req) := {"status_code": 200, "body": {"requester": {"reference": org_a}}} if {
	contains(req.url, "/Task/")
	not req.headers.Authorization
}

test_backend_auth_attached_when_set if {
	data.umzh.authz.allow with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, "")
		with opa.runtime as {"env": {"FHIR_BACKEND_AUTHORIZATION": "Basic dGVzdDp0ZXN0"}}
		with http.send as mock_task_a_auth
}

test_backend_auth_absent_when_unset if {
	every env in [{}, {"FHIR_BACKEND_AUTHORIZATION": ""}] {
		data.umzh.authz.allow with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, "")
			with opa.runtime as {"env": env}
			with http.send as mock_task_a_noauth
	}
}

# The input can't set the credential either.
test_backend_auth_not_from_input if {
	data.umzh.authz.allow with input as object.union(
		req_in("GET", "Task", "t1", "system/Task.r", org_a, ""),
		{"fhir_authorization": "Basic dGVzdDp0ZXN0"},
	)
		with opa.runtime as {"env": {}}
		with http.send as mock_task_a_noauth
}

# No rule in either package holds the credential, so OPA's data API can't return
# it: GET /v1/data/umzh/authz evaluates every rule, but no function.
test_backend_auth_in_no_rule if {
	doc := data.umzh.authz with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, "")
		with opa.runtime as {"env": {"FHIR_BACKEND_AUTHORIZATION": "Basic c2VjcmV0"}}
		with http.send as mock_task_a_auth
	not contains(json.marshal(doc), "c2VjcmV0")
}

# ============================================================================
# Rule 1c — Task create (caller is Task.requester, no Task.output)
# ============================================================================
test_1c_create_allowed if {
	data.umzh.authz.allow with input as create_in(new_task)
}

test_1c_denied_without_scope if {
	not data.umzh.authz.allow with input as object.union(create_in(new_task), {"scope": "system/Task.r"})
}

test_1c_denied_other_requester if {
	not data.umzh.authz.allow with input as create_in(object.union(new_task, {"requester": {"reference": org_x}}))
}

test_1c_denied_empty_org if {
	not data.umzh.authz.allow with input as object.union(
		create_in(object.union(new_task, {"requester": {"reference": ""}})),
		{"organization_reference": ""},
	)
}

test_1c_denied_with_fulfiller_field if {
	every field in [
		{"output": [{"valueReference": {"reference": "Patient/p1"}}]},
		{"output": []},
		{"output": false},
		{"_output": {"id": "x"}},
		{"businessStatus": {"coding": [{"code": "awaiting-information"}]}},
		{"_businessStatus": {"id": "x"}},
	] {
		not data.umzh.authz.allow with input as create_in(object.union(new_task, field))
	}
}

# ============================================================================
# Rule 1d — Task update: who may update
# ============================================================================
test_1d_denied_other_requester if {
	not data.umzh.authz.allow with input as update_in(cancelled_task)
		with http.send as mock_other_requester
}

test_1d_denied_without_scope if {
	not data.umzh.authz.allow with input as object.union(update_in(cancelled_task), {"scope": "system/Task.r"})
		with http.send as mock_requested
}

test_1d_denied_unknown_id if {
	not data.umzh.authz.allow with input as update_in(cancelled_task)
		with http.send as mock_not_found
}

# --- If-Match: a stale or missing version is reported, but only to the requester
test_1d_denied_wrong_version if {
	every if_match in [`W/"2"`, ""] {
		wrong := object.union(update_in(cancelled_task), {"header_if_match": if_match})
		not data.umzh.authz.allow with input as wrong
			with http.send as mock_requested
		data.umzh.authz.task_version_mismatch with input as wrong
			with http.send as mock_requested
	}
}

test_1d_version_mismatch_hidden_from_others if {
	not data.umzh.authz.task_version_mismatch with input as object.union(update_in(stored_task), {"header_if_match": `W/"2"`})
		with http.send as mock_other_requester
}

# --- Cancel: while requested or accepted, adding at most a statusReason ------
test_1d_cancel_allowed if {
	data.umzh.authz.allow with input as update_in(cancelled_task)
		with http.send as mock_requested
}

test_1d_cancel_accepted_allowed if {
	data.umzh.authz.allow with input as update_in(cancelled_task)
		with http.send as mock_accepted
}

test_1d_cancel_with_reason_allowed if {
	data.umzh.authz.allow with input as update_in(object.union(cancelled_task, {"statusReason": {"text": "entered in error"}}))
		with http.send as mock_requested
}

test_1d_cancel_denied_in_progress if {
	not data.umzh.authz.allow with input as update_in(cancelled_task)
		with http.send as mock_in_progress
}

test_1d_cancel_denied_changing_reason if {
	not data.umzh.authz.allow with input as update_in(object.union(cancelled_task, {"statusReason": {"text": "new"}}))
		with http.send as mock_has_reason
}

test_1d_denied_other_change if {
	every change in [
		{"status": "completed"},
		{"status": "requested"},
		{"focus": {"reference": "ServiceRequest/other"}},
		{"owner": {"reference": org_x}},
		{"requester": {"reference": org_x}},
		{"output": [{"valueReference": {"reference": "Patient/p1"}}]},
	] {
		not data.umzh.authz.allow with input as update_in(object.union(cancelled_task, change))
			with http.send as mock_requested
	}
}

test_1d_denied_body_not_a_task if {
	every body in [{}, []] {
		not data.umzh.authz.allow with input as update_in(body)
			with http.send as mock_awaiting
	}
}

test_1d_ignores_server_fields if {
	data.umzh.authz.allow with input as update_in(object.union(object.remove(cancelled_task, ["meta"]), {
		"text": {"status": "generated"},
		"lastModified": "2026-01-01",
	}))
		with http.send as mock_requested
}

# --- Answer: while awaiting information, add input and clear businessStatus --
test_1d_answer_allowed if {
	data.umzh.authz.allow with input as update_in(answered_task)
		with http.send as mock_awaiting
}

test_1d_answer_new_entry_anywhere_allowed if {
	every entries in [
		[{"valueString": "first"}, {"valueString": "second"}, {"valueString": "new"}],
		[{"valueString": "new"}, {"valueString": "first"}, {"valueString": "second"}],
	] {
		data.umzh.authz.allow with input as update_in(object.union(answered_task, {"input": entries}))
			with http.send as mock_awaiting_with_input
	}
}

# Stored entries stay unchanged, and at least one is added.
test_1d_answer_denied_for_bad_input if {
	every entries in [
		[{"valueString": "first"}, {"valueString": "second"}],
		[{"valueString": "second"}, {"valueString": "first"}],
		[{"valueString": "changed"}, {"valueString": "second"}, {"valueString": "new"}],
		{"a": {"valueString": "first"}, "b": {"valueString": "second"}, "c": {"valueString": "new"}},
	] {
		not data.umzh.authz.allow with input as update_in(object.union(answered_task, {"input": entries}))
			with http.send as mock_awaiting_with_input
	}
}

test_1d_answer_denied_for_other_business_status if {
	not data.umzh.authz.allow with input as update_in(answered_task)
		with http.send as mock_other_business_status
}

test_1d_answer_denied_changing_business_status if {
	not data.umzh.authz.allow with input as update_in(object.union(answered_task, {"businessStatus": {"coding": [{"code": "other"}]}}))
		with http.send as mock_awaiting
}

test_1d_answer_denied_with_other_change if {
	not data.umzh.authz.allow with input as update_in(object.union(answered_task, {"output": [{"valueReference": {"reference": "Patient/p1"}}]}))
		with http.send as mock_awaiting
}

# ============================================================================
# Rule 3 — Questionnaire
# ============================================================================
test_3_questionnaire_read if {
	data.umzh.authz.allow with input as req_in("GET", "Questionnaire", "q1", "system/Questionnaire.r", org_a, "")
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

test_4_denied_sr_not_active if {
	not data.umzh.authz.allow with input as req_in("GET", "Patient", "p1", "system/Patient.r", org_a, sr_ctx)
		with http.send as mock_sr_revoked
}

test_4_denied_blank_id if {
	not data.umzh.authz.allow with input as req_in("GET", "Patient", "", "system/Patient.r", org_a, sr_ctx)
		with http.send as mock_sr_blank_ref
}

# The fetch would read the old, still active version.
test_4_denied_versioned_context if {
	not data.umzh.authz.allow with input as req_in("GET", "Patient", "p1", "system/Patient.r", org_a, ["ServiceRequest/sr1/_history/1"])
		with http.send as mock_sr_ok
}

# ============================================================================
# Rule 4 — QuestionnaireResponse (basedOn back-reference or forward pointer)
# ============================================================================
test_4_qr_allowed_via_based_on if {
	data.umzh.authz.allow with input as req_in("GET", "QuestionnaireResponse", "qr1", "system/QuestionnaireResponse.r", org_a, sr_ctx)
		with http.send as mock_qr_relative
}

test_4_qr_allowed_via_supporting_info if {
	data.umzh.authz.allow with input as req_in("GET", "QuestionnaireResponse", "qr1", "system/QuestionnaireResponse.r", org_a, sr_ctx)
		with http.send as mock_qr_forward
}

test_4_qr_denied_for_other_root if {
	not data.umzh.authz.allow with input as req_in("GET", "QuestionnaireResponse", "qr1", "system/QuestionnaireResponse.r", org_a, sr_ctx)
		with http.send as mock_qr_other_root
}

test_4_qr_denied_for_other_server if {
	not data.umzh.authz.allow with input as req_in("GET", "QuestionnaireResponse", "qr1", "system/QuestionnaireResponse.r", org_a, sr_ctx)
		with http.send as mock_qr_other_server
}

# The IG's condition for trusting basedOn: only the Placer writes these.
test_4_qr_writes_denied if {
	every method in ["POST", "PUT", "PATCH", "DELETE"] {
		not data.umzh.authz.allow with input as req_in(method, "QuestionnaireResponse", "qr1", "system/QuestionnaireResponse.cruds", org_a, sr_ctx)
			with http.send as mock_qr_relative
	}
}

# ============================================================================
# Rule 4b — Task graph (placer reading Task output)
# ============================================================================
test_4b_task_output_read_allowed if {
	data.umzh.authz.allow with input as req_in("GET", "DocumentReference", "d1", "system/DocumentReference.r", org_a, task_ctx)
		with http.send as mock_task_ctx_ok
}

test_4b_denied_other_requester if {
	not data.umzh.authz.allow with input as req_in("GET", "DocumentReference", "d1", "system/DocumentReference.r", org_a, task_ctx)
		with http.send as mock_task_ctx_other
}

test_4b_denied_blank_id if {
	not data.umzh.authz.allow with input as req_in("GET", "Patient", "", "system/Patient.r", org_a, task_ctx)
		with http.send as mock_task_blank_ref
}

# The fetch would read an old version, with outputs since removed.
test_4b_denied_versioned_context if {
	not data.umzh.authz.allow with input as req_in("GET", "DocumentReference", "d1", "system/DocumentReference.r", org_a, ["Task/t1/_history/1"])
		with http.send as mock_task_ctx_ok
}

# The Placer fills Task.input, so it must not extend what the Placer can read.
test_4b_task_input_not_in_graph if {
	not data.umzh.authz.allow with input as req_in("GET", "Patient", "p9", "system/Patient.r", org_a, task_ctx)
		with http.send as mock_task_ctx_input
}

# ============================================================================
# Rule 5 — metadata (always)
# ============================================================================
test_5_metadata_allowed if {
	data.umzh.authz.allow with input as {"method": "GET", "path": "/fhir/metadata", "query_params": [], "organization_reference": "", "scope": "", "context": ""}
}

# ============================================================================
# Scope syntax — combined SMART v2 letters are honored; wildcards are NOT
# ============================================================================

# One combined scope (system/Task.crus) satisfies every single-action Task check.
test_combined_scope_task_search if {
	data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/Task.crus", org_a, "")
}

test_combined_scope_task_create if {
	data.umzh.authz.allow with input as object.union(create_in(new_task), {"scope": "system/Task.crus"})
}

# Wildcard resource scopes are NOT supported: `system/*.r` must not grant a read
# on a concrete type (has_smart_scope matches the resource literally).
test_wildcard_scope_denied if {
	not data.umzh.authz.allow with input as req_in("GET", "Questionnaire", "q1", "system/*.r", org_a, "")
}

test_wildcard_scope_denied_task if {
	not data.umzh.authz.allow with input as req_in("GET", "Task", "", "system/*.crus", org_a, "")
}

# ============================================================================
# Cross-cutting — a resource read with no context/consent is denied
# ============================================================================
test_uncontexted_read_denied if {
	not data.umzh.authz.allow with input as req_in("GET", "Patient", "p1", "system/Patient.r", org_a, "")
}

test_uncontexted_directory_read_denied if {
	not data.umzh.authz.allow with input as req_in("GET", "Organization", "o1", "system/Organization.r", org_a, "")
}

# ============================================================================
# Cross-cutting — a token carries exactly one context. The adapter sends "" for
# none or several (adapter_test.rego); a context that isn't a plain reference to
# a ServiceRequest or Task is denied too.
# ============================================================================
test_4_denied_without_usable_context if {
	every ctx in ["", "ServiceRequest/sr1/_history/1", "Patient/p1"] {
		not data.umzh.authz.allow with input as req_in("GET", "Patient", "p1", "system/Patient.r", org_a, ctx)
			with http.send as mock_sr_ok
	}
}

# query_params is optional: no entry means no _include.
# query_params is optional and defaults to [].
test_query_params_default_empty if {
	data.umzh.authz.allow with input as object.remove(req_in("GET", "Task", "", "system/Task.s", org_a, ""), ["query_params"])
}

# null is the adapter's "couldn't parse": a GET search depends on its query
# parameters, so it's denied; a read names its resource in the path, and a write's
# query decides nothing, so they're still decided.
test_null_query_params_denies_only_get_search if {
	not data.umzh.authz.allow with input as object.union(req_in("GET", "Task", "", "system/Task.s", org_a, ""), {"query_params": null})
	data.umzh.authz.allow with input as object.union(req_in("GET", "Task", "t1", "system/Task.r", org_a, ""), {"query_params": null})
		with http.send as mock_task_a
	data.umzh.authz.allow with input as object.union(create_in(new_task), {"query_params": null})
}

# query_params must be a list of {name: value} entries.
test_get_search_query_params_not_a_list_denied if {
	every query_params in [{"_id": "t1"}, "_id=t1", null, ["_id=t1"]] {
		not data.umzh.authz.allow with input as object.union(search_in("Task", "t1", "system/Task.s", ""), {"query_params": query_params})
			with http.send as mock_task_a
	}
}

# A repeated _id is ANDed by the FHIR server; OPA won't pick one of them.
test_get_search_with_two_ids_denied if {
	data.umzh.authz.allow with input as search_in("Task", "t1", "system/Task.s", "")
		with http.send as mock_task_a
	not data.umzh.authz.allow with input as object.union(search_in("Task", "t1", "system/Task.s", ""), {"query_params": [{"_id": "t1"}, {"_id": "t2"}]})
		with http.send as mock_task_a
}

# ============================================================================
# Cross-cutting — a search needs s
# ============================================================================
test_1b_search_denied_with_r_only if {
	not data.umzh.authz.allow with input as search_in("Task", "t1", "system/Task.r", "")
		with http.send as mock_task_a
}

test_3_search_denied_with_r_only if {
	not data.umzh.authz.allow with input as search_in("Questionnaire", "", "system/Questionnaire.r", "")
}

test_4_search_denied_with_r_only if {
	not data.umzh.authz.allow with input as search_in("Patient", "p1", "system/Patient.r", sr_ctx)
		with http.send as mock_sr_ok
}

test_4b_search_denied_with_r_only if {
	not data.umzh.authz.allow with input as search_in("DocumentReference", "d1", "system/DocumentReference.r", task_ctx)
		with http.send as mock_task_ctx_ok
}

# ============================================================================
# read vs search — from the path: method and resource_id can't tell them apart
# ============================================================================
test_read_action_from_path if {
	data.umzh.authz.read_action == "r" with input as {"method": "GET", "path": "/fhir/Task/t1"}
	data.umzh.authz.read_action == "s" with input as {"method": "GET", "path": "/fhir/Task"}
	data.umzh.authz.read_action == "s" with input as {"method": "GET", "path": "/fhir/metadata"}
	# Only a GET is a read or a search.
	not data.umzh.authz.read_action with input as {"method": "POST", "path": "/fhir/Task"}
	# Anything deeper than /fhir/<type>/<id> is neither.
	not data.umzh.authz.read_action with input as {"method": "GET", "path": "/fhir/Task/t1/_history/1"}
	not data.umzh.authz.read_action with input as {"method": "GET", "path": "/fhir/Task/"}
}

# GET /Task/t1 and GET /Task?_id=t1 have the same method and resource_id, but the
# search needs s and the read r.
test_same_id_read_needs_r_search_needs_s if {
	data.umzh.authz.allow with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, "")
		with http.send as mock_task_a
	not data.umzh.authz.allow with input as search_in("Task", "t1", "system/Task.r", "")
		with http.send as mock_task_a
	data.umzh.authz.allow with input as search_in("Task", "t1", "system/Task.s", "")
		with http.send as mock_task_a
}

# ============================================================================
# The request — type and id come from the path and the query, not the input
# ============================================================================
test_resource_from_path_and_id if {
	data.umzh.authz.requested_ref == "Patient/p1" with input as {"method": "GET", "path": "/fhir/Patient/p1"}
	data.umzh.authz.requested_ref == "Patient/p1" with input as {"method": "GET", "path": "/fhir/Patient", "query_params": [{"_id": "p1"}]}
	data.umzh.authz.resource_id == "" with input as {"method": "GET", "path": "/fhir/Patient"}
	# Two _id values name no single resource (and the search is denied).
	data.umzh.authz.resource_id == "" with input as {"method": "GET", "path": "/fhir/Patient", "query_params": [{"_id": "p1"}, {"_id": "p2"}]}
}

# An id in the input is ignored: only the path and _id name the resource.
test_input_resource_id_ignored if {
	data.umzh.authz.requested_ref == "Task/t1" with input as {"method": "GET", "path": "/fhir/Task/t1", "resource_type": "Patient", "resource_id": "t2"}
}

# A path deeper than /fhir/<type>/<id> targets nothing OPA can name: denied, even
# where the id and the caller would otherwise pass.
test_deeper_path_denied if {
	not data.umzh.authz.allow with input as object.union(req_in("GET", "Task", "t1", "system/Task.r", org_a, ""), {"path": "/fhir/Task/t1/_history/1"})
		with http.send as mock_task_a
	not data.umzh.authz.allow with input as object.union(create_in(new_task), {"path": "/fhir/Task/t1"})
	not data.umzh.authz.allow with input as object.union(update_in(cancelled_task), {"path": "/fhir/Task/t1/_history/3"})
		with http.send as mock_task_a
}

# Rule 5 is the CapabilityStatement read, not every method on its path.
test_5_metadata_only_get if {
	every method in ["POST", "PUT", "DELETE"] {
		not data.umzh.authz.allow with input as {"method": method, "path": "/fhir/metadata", "query_params": [], "organization_reference": "", "scope": "", "context": ""}
	}
}

# The 412 needs everything a decision needs: no FHIR server, no 412.
test_version_mismatch_needs_admissible if {
	not data.umzh.authz.task_version_mismatch with input as object.union(update_in(stored_task), {"header_if_match": `W/"2"`})
		with http.send as mock_task_a
		with opa.runtime as {"env": {}}
		with data.config as {}
}
