# =============================================================================
# adapter_test.rego — unit tests for the APISIX request adapter in
# opa/policies/gateway.rego (package umzh.authz.gateway): path/query → the
# resource_type / resource_id / canonical_path it hands to main.rego.
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

# The adapter hands _include values to main.rego, which decides on them.
test_task_output_include_denied_without_context if {
	data.umzh.authz.gateway.allow == false with input as {"request": {
		"method": "GET", "path": "/fhir/Task",
		"query": {"_include": "Task:output-value-reference"},
		"headers": _bearer,
	}}
		with data.config as {"fhir_base": "http://hapi/fhir/clinical-orders"}
}

# --- Refused here, whatever main.rego decides --------------------------------
_bearer := {"authorization": sprintf("Bearer %s", [_task_token])}

_decide(request) := allow if {
	allow := data.umzh.authz.gateway.allow with input as {"request": request}
		with data.umzh.authz.allow as true
		with data.config as {"fhir_base": "http://hapi/fhir/clinical-orders"}
}

_get(path, query) := {"method": "GET", "path": path, "query": query, "headers": _bearer}

test_valid_id_allowed if {
	_decide(_get("/fhir/QuestionnaireResponse", {"_id": "Ab-1.2"})) == true
}

# OPA's fetch stops at the #, while HAPI's search returns victim.
test_smuggled_id_denied if {
	_decide(_get("/fhir/QuestionnaireResponse", {"_id": "good#/QuestionnaireResponse/victim"})) == false
}

test_get_without_query_denied if {
	_decide({"method": "GET", "path": "/fhir/Task", "headers": _bearer}) == false
}

# A raw query string would hide its _include from the gate just the same.
test_non_object_query_denied if {
	every query in ["_include=Task:output-value-reference", null, ["_include=Task:output-value-reference"]] {
		_decide(_get("/fhir/Task", query)) == false
	}
}

# Only Task has the gate that needs query: /fhir/metadata and other reads don't.
test_other_type_without_query_allowed if {
	_decide({"method": "GET", "path": "/fhir/metadata", "headers": _bearer}) == true
}

test_task_read_without_query_allowed if {
	_decide({"method": "GET", "path": "/fhir/Task/t1", "headers": _bearer}) == true
}

test_post_without_query_allowed if {
	_decide({"method": "POST", "path": "/fhir/Task", "headers": _bearer}) == true
}

test_if_none_exist_denied if {
	every name in ["if-none-exist", "If-None-Exist"] {
		_decide({"method": "POST", "path": "/fhir/Task", "headers": object.union(_bearer, {name: "_id=victim"})}) == false
	}
}

test_write_on_wrong_path_denied if {
	every request in [
		{"method": "PUT", "path": "/fhir/Task/t1/_history/1"},
		{"method": "POST", "path": "/fhir/Task/t1/_history/1"},
		{"method": "POST", "path": "/fhir/Task/t1"},
		{"method": "PUT", "path": "/fhir/Task", "query": {"_id": "t1"}},
	] {
		_decide(object.union(request, {"headers": _bearer})) == false
	}
}

# --- Writes through the real main.rego ---------------------------------------
_create(body) := {"method": "POST", "path": "/fhir/Task", "body": body, "headers": _bearer}

_write(body, headers) := {"method": "PUT", "path": "/fhir/Task/t1", "body": body, "headers": object.union(_bearer, headers)}

_created := `{"resourceType":"Task","requester":{"reference":"http://x/Organization/A"}}`

_cancelled := `{"resourceType":"Task","status":"cancelled","requester":{"reference":"http://x/Organization/A"}}`

_stored_task(_) := {"status_code": 200, "body": {
	"resourceType": "Task",
	"meta": {"versionId": "3"},
	"status": "requested",
	"requester": {"reference": "http://x/Organization/A"},
}}

_real_decision(request) := decision if {
	decision := data.umzh.authz.gateway.decision with input as {"request": request}
		with data.config as {"fhir_base": "http://hapi/fhir/clinical-orders"}
		with http.send as _stored_task
}

test_create_decided_on_the_body if {
	_real_decision(_create(_created)).allow == true
}

test_update_decided_on_body_and_version if {
	_real_decision(_write(_cancelled, {"if-match": `W/"3"`})).allow == true
}

test_wrong_version_answers_412 if {
	every headers in [{"if-match": `W/"2"`}, {}] {
		_real_decision(_write(_cancelled, headers)) == {"allow": false, "status_code": 412}
	}
}

test_refused_writes_keep_403 if {
	every request in [
		{"method": "POST", "path": "/fhir/Task", "headers": _bearer},
		_write("<Task/>", {"if-match": `W/"3"`}),
		_write(`{"status":"completed"}`, {"if-match": `W/"3"`}),
		object.union(_write(_cancelled, {}), {"path": "/fhir/Task/t1/_history/1"}),
		object.union(_write(_cancelled, {}), {"path": "/fhir/Task/t1#x"}),
		_write(_cancelled, {"if-none-exist": "_id=x"}),
	] {
		_real_decision(request) == {"allow": false, "status_code": 403}
	}
}

# --- _include values: a lone value is a string, repeated ones an array -------
_with_query(query) := {"request": {"path": "/fhir/Task", "query": query, "headers": {}}}

test_includes_lone_value if {
	data.umzh.authz.gateway.includes == ["Task:output-value-reference"] with input as _with_query({"_include": "Task:output-value-reference"})
}

test_includes_repeated_value if {
	data.umzh.authz.gateway.includes == ["A:a", "B:b"] with input as _with_query({"_include": ["A:a", "B:b"]})
}

test_includes_any_modifier if {
	includes := data.umzh.authz.gateway.includes with input as _with_query({
		"_include": "A:a",
		"_include:iterate": ["B:b", "C:c"],
		"_include:recurse": "D:d",
	})
	{value | some value in includes} == {"A:a", "B:b", "C:c", "D:d"}
}

# A bare `?_include` reaches OPA as a boolean: kept, so the policy can refuse it.
test_includes_keeps_non_string_value if {
	data.umzh.authz.gateway.includes == [true] with input as _with_query({"_include": true})
}

# --- fhir_base resolution: env override vs data document ---------------------
# Default: no FHIR_BASE env → fhir_base comes from the opa-config.json data doc.
test_fhir_base_from_data_config if {
	data.umzh.authz.gateway.fhir_base == "http://cfg/fhir/clinical-orders" with opa.runtime as {"env": {}}
		with data.config as {"fhir_base": "http://cfg/fhir/clinical-orders"}
}

# A non-empty FHIR_BASE env overrides the data document (external-backend case).
test_fhir_base_env_override_wins if {
	data.umzh.authz.gateway.fhir_base == "https://external/fhir" with opa.runtime as {"env": {"FHIR_BASE": "https://external/fhir"}}
		with data.config as {"fhir_base": "http://cfg/fhir/clinical-orders"}
}

# An empty FHIR_BASE env is ignored → falls back to the data document.
test_fhir_base_empty_env_falls_back if {
	data.umzh.authz.gateway.fhir_base == "http://cfg/fhir/clinical-orders" with opa.runtime as {"env": {"FHIR_BASE": ""}}
		with data.config as {"fhir_base": "http://cfg/fhir/clinical-orders"}
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
