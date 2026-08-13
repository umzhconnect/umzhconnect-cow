# =============================================================================
# adapter_test.rego — unit tests for the APISIX request adapter in
# opa/policies/gateway.rego (package umzh.authz.gateway): path/query → the
# resource_type / resource_id / canonical_path it hands to main.rego. Pure (no
# http.send), so no mocks needed.
# =============================================================================
package umzh.authz.gateway_test

import rego.v1

read_by_id := {"request": {"path": "/fhir/Patient/123", "query": {}, "headers": {}}}

search_with_id := {"request": {"path": "/fhir/ServiceRequest", "query": {"_id": "abc"}, "headers": {}}}

search_no_id := {"request": {"path": "/fhir/Task", "query": {}, "headers": {}}}

# Read by id → type + id come from the path.
test_read_by_id_type if {
	data.umzh.authz.gateway.resource_type == "Patient" with input as read_by_id
}

test_read_by_id_id if {
	data.umzh.authz.gateway.resource_id == "123" with input as read_by_id
}

test_read_by_id_canonical if {
	data.umzh.authz.gateway.canonical_path == "/fhir/Patient/123" with input as read_by_id
}

# Search with _id → id comes from the query, canonical_path folds it in.
test_search_with_id_type if {
	data.umzh.authz.gateway.resource_type == "ServiceRequest" with input as search_with_id
}

test_search_with_id_id if {
	data.umzh.authz.gateway.resource_id == "abc" with input as search_with_id
}

test_search_with_id_canonical if {
	data.umzh.authz.gateway.canonical_path == "/fhir/ServiceRequest/abc" with input as search_with_id
}

# --- Decision is an EXPLICIT boolean (default allow := false) ----------------
# A minimal alg:none JWT (io.jwt.decode doesn't verify) carrying a Task scope.
_task_token := sprintf("%s.%s.sig", [
	base64url.encode_no_pad(`{"alg":"none","typ":"JWT"}`),
	base64url.encode_no_pad(`{"scope":"system/Task.crus","extensions":{"umzhconnect":{"organization_reference":"http://x/Organization/A"}},"fhirContext":[]}`),
])

# No bearer → denied → must be an explicit false (not undefined).
test_allow_false_when_no_token if {
	data.umzh.authz.gateway.allow == false with input as search_no_id
}

# Valid Task scope → Task search (Rule 1a) allowed. Mock data.config (the
# opa-config.json data document isn't loaded by `opa test`); Rule 1a does no
# http.send, so fhir_base just needs to be present.
test_allow_true_task_search if {
	data.umzh.authz.gateway.allow == true with input as {"request": {
		"method": "GET", "path": "/fhir/Task", "query": {},
		"headers": {"authorization": sprintf("Bearer %s", [_task_token])},
	}}
		with data.config as {"fhir_base": "http://hapi/fhir/clinical-orders"}
}

# Search with no id → empty resource_id, canonical_path is the raw path.
test_search_no_id_type if {
	data.umzh.authz.gateway.resource_type == "Task" with input as search_no_id
}

test_search_no_id_empty_id if {
	data.umzh.authz.gateway.resource_id == "" with input as search_no_id
}

test_search_no_id_canonical if {
	data.umzh.authz.gateway.canonical_path == "/fhir/Task" with input as search_no_id
}
