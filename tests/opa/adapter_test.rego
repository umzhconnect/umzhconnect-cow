# =============================================================================
# adapter_test.rego — unit tests for the APISIX request adapter in
# opa/policies/gateway.rego (package umzh.authz.gateway): path and raw query
# string → the input it hands to main.rego, and what main.rego reads from it.
# =============================================================================
package umzh.authz.gateway_test

import rego.v1

read_by_id := {"request": {"path": "/fhir/Patient/123", "query_string": "", "headers": {}}}

search_with_id := {"request": {"path": "/fhir/ServiceRequest", "query_string": "_id=abc", "headers": {}}}

search_no_id := {"request": {"path": "/fhir/Task", "query_string": "", "headers": {}}}

# What main.rego reads from the input the adapter builds for <request>.  (Not the
# whole data.umzh.authz document: it contains this test package.)
_main(request) := {"resource_type": resource_type, "resource_id": resource_id} if {
	policy_input := data.umzh.authz.gateway._policy_input with input as request
	resource_type := data.umzh.authz.resource_type with input as policy_input
	resource_id := data.umzh.authz.resource_id with input as policy_input
}

# Read by id → type + id come from the path.
test_read_by_id_type_and_id if {
	_main(read_by_id).resource_type == "Patient"
	_main(read_by_id).resource_id == "123"
}

# Search with _id → id comes from the query.
test_search_with_id_type_and_id if {
	_main(search_with_id).resource_type == "ServiceRequest"
	_main(search_with_id).resource_id == "abc"
}

# --- Decision is an EXPLICIT boolean (default allow := false) ----------------
# A minimal alg:none JWT (io.jwt.decode doesn't verify) carrying a Task scope.
_task_token := sprintf("%s.%s.sig", [
	base64url.encode_no_pad(`{"alg":"none","typ":"JWT"}`),
	base64url.encode_no_pad(`{"scope":"system/Task.crus","extensions":{"umzhconnect":{"organization_reference":"http://x/Organization/A"}}}`),
])

_bearer := {"authorization": sprintf("Bearer %s", [_task_token])}

# A Task search with this raw query string.
_task_search(query_string) := {"request": {
	"method": "GET", "path": "/fhir/Task", "query_string": query_string, "headers": _bearer,
}}

# No bearer → denied → must be an explicit false (not undefined).
test_allow_false_when_no_token if {
	data.umzh.authz.gateway.allow == false with input as search_no_id
}

# Valid Task scope → Task search (Rule 1a) allowed. Rule 1a does no http.send.
test_allow_true_task_search if {
	data.umzh.authz.gateway.allow == true with input as _task_search("")
}

# The adapter hands _include values to main.rego, which decides on them.
test_task_output_include_denied_without_context if {
	data.umzh.authz.gateway.allow == false with input as _task_search("_include=Task:output-value-reference")
}

# _include needs _id, whichever value it is.
test_include_without_id_denied if {
	every query_string in [
		"_include=Task:output-value-canonical",
		"_include:iterate=DiagnosticReport:result",
	] {
		data.umzh.authz.gateway.allow == false with input as _task_search(query_string)
	}
}

test_include_with_id_allowed if {
	data.umzh.authz.gateway.allow == true with input as _task_search("_id=t1&_include=Task:output-value-canonical")
		with http.send as _stored_task
}

# --- The raw query string: OPA parses it, and denies what it can't -----------

# A missing query string is a consumer that didn't forward it: OPA can't see the
# _id or the includes, so it allows nothing, not even a Task search.
test_missing_query_string_denied if {
	every request in [
		{"method": "GET", "path": "/fhir/Task", "headers": _bearer},
		{"method": "GET", "path": "/fhir/Task", "query_string": null, "headers": _bearer},
		{"method": "GET", "path": "/fhir/Task", "query_string": {}, "headers": _bearer},
		# The old object format isn't read as an empty query.
		{"method": "GET", "path": "/fhir/Task", "query": {"_include": "Task:output-value-reference"}, "headers": _bearer},
	] {
		data.umzh.authz.gateway.allow == false with input as {"request": request}
	}
}

# Malformed: bad percent-encoding, or `;` as a separator. Denied, not read as empty.
test_malformed_query_string_denied if {
	every query_string in ["_include=%zz", "_id=t1;_include=Task:output-value-reference"] {
		data.umzh.authz.gateway.allow == false with input as _task_search(query_string)
	}
}

# A repeated _id is ANDed by the FHIR server; OPA won't pick one of them.
test_repeated_id_denied if {
	data.umzh.authz.gateway.allow == false with input as _task_search("_id=t1&_id=t2")
		with http.send as _stored_task
}

# Percent-encoding is decoded before the rules see the values.
test_query_string_decoded if {
	_main(_task_search("_id=%74%31")).resource_id == "t1"
	data.umzh.authz.gateway._query_params == [{"_include": "Task:output-value-reference"}] with input as _task_search("_include=Task%3Aoutput-value-reference")
}

# --- Writes through the real main.rego ---------------------------------------
_create(body) := {"method": "POST", "path": "/fhir/Task", "query_string": "", "body": body, "headers": _bearer}

_write(body, headers) := {"method": "PUT", "path": "/fhir/Task/t1", "query_string": "", "body": body, "headers": object.union(_bearer, headers)}

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
		with http.send as _stored_task
}

# The body may arrive as the raw string or as the same JSON object: the decision is
# the same either way.
test_body_as_string_or_object if {
	every body in [_created, json.unmarshal(_created)] {
		_real_decision(_create(body)) == {"allow": true}
	}
	every body in [_cancelled, json.unmarshal(_cancelled)] {
		_real_decision(_write(body, {"if-match": `W/"3"`})) == {"allow": true}
	}
	# A completed status isn't a change the Placer may make, in either form.
	every body in [`{"status":"completed"}`, {"status": "completed"}] {
		_real_decision(_write(body, {"if-match": `W/"3"`})) == {"allow": false, "status_code": 403}
	}
}

# What main.rego receives as the body.
test_body_parsing if {
	every request_body, expected in {
		`{"resourceType":"Task"}`: {"resourceType": "Task"},
		"<Task/>": {},
		"": {},
		`[1,2]`: [1, 2],
	} {
		data.umzh.authz.gateway._body == expected with input as {"request": {"body": request_body}}
	}
	data.umzh.authz.gateway._body == {"resourceType": "Task"} with input as {"request": {"body": {"resourceType": "Task"}}}
	every request_body in [null, [{"resourceType": "Task"}], 42] {
		data.umzh.authz.gateway._body == {} with input as {"request": {"body": request_body}}
	}
	data.umzh.authz.gateway._body == {} with input as {"request": {}}
}

test_create_decided_on_the_body if {
	_real_decision(_create(_created)) == {"allow": true}
}

test_update_decided_on_body_and_version if {
	_real_decision(_write(_cancelled, {"if-match": `W/"3"`})) == {"allow": true}
}

test_wrong_version_answers_412 if {
	every headers in [{"if-match": `W/"2"`}, {}] {
		_real_decision(_write(_cancelled, headers)) == {"allow": false, "status_code": 412}
	}
}

test_refused_writes_keep_403 if {
	every request in [
		{"method": "POST", "path": "/fhir/Task", "query_string": "", "headers": _bearer},
		_write("<Task/>", {"if-match": `W/"3"`}),
		_write(`{"status":"completed"}`, {"if-match": `W/"3"`}),
	] {
		_real_decision(request) == {"allow": false, "status_code": 403}
	}
}

# A write's query decides nothing: without a query string, a stale If-Match is
# still a 412.
test_write_without_query_string_still_decided if {
	_real_decision(object.remove(_write(_cancelled, {"if-match": `W/"2"`}), ["query_string"])) == {"allow": false, "status_code": 412}
}

# A query that doesn't parse reaches main.rego as query_params null, not [].
test_unparsed_query_is_null if {
	every request in [
		{"method": "GET", "path": "/fhir/Task", "headers": _bearer},
		{"method": "GET", "path": "/fhir/Task", "query_string": "_include=%zz", "headers": _bearer},
	] {
		policy_input := data.umzh.authz.gateway._policy_input with input as {"request": request}
		policy_input.query_params == null
	}
	data.umzh.authz.gateway._policy_input.query_params == [] with input as _task_search("")
}

# --- query_params: every value of every parameter, one entry each ------------
_with_query(query_string) := {"request": {"path": "/fhir/Task", "query_string": query_string, "headers": {}}}

test_query_params_lone_value if {
	data.umzh.authz.gateway._query_params == [{"_include": "Task:output-value-reference"}] with input as _with_query("_include=Task:output-value-reference")
}

# A repeated parameter keeps every value: none is lost as with a duplicate JSON key.
test_query_params_repeated_value if {
	data.umzh.authz.gateway._query_params == [{"_include": "A:a"}, {"_include": "B:b"}] with input as _with_query("_include=A:a&_include=B:b")
}

test_query_params_every_parameter if {
	params := data.umzh.authz.gateway._query_params with input as _with_query("_id=t1&_include=A:a&_include:iterate=B:b&_include:iterate=C:c&_include:recurse=D:d")
	{param | some param in params} == {{"_id": "t1"}, {"_include": "A:a"}, {"_include:iterate": "B:b"}, {"_include:iterate": "C:c"}, {"_include:recurse": "D:d"}}
}

# A bare `?_include` is an empty value: kept, so the policy can refuse it.
test_query_params_keep_empty_value if {
	data.umzh.authz.gateway._query_params == [{"_include": ""}] with input as _with_query("_include")
}

# --- Token context and scope action ------------------------------------------
# Entries of other types don't count: this token still has exactly one context.
test_context_and_search_scope_reach_main if {
	claims := {
		"scope": "system/Task.s",
		"extensions": {"umzhconnect": {"organization_reference": "http://x/Organization/A"}},
		"authorization_details": [
			{"type": "http://fhir.ch/ig/ch-umzh-connect/context", "identifier": "Task/t1"},
			{"type": "umzh-connect-context", "identifier": "Task/t2"},
		],
	}
	bearer := sprintf("Bearer %s.%s.sig", [base64url.encode_no_pad(`{"alg":"none","typ":"JWT"}`), base64url.encode_no_pad(json.marshal(claims))])
	_real_decision({
		"method": "GET", "path": "/fhir/Task",
		"query_string": "_id=t1&_include=Task:output-value-reference",
		"headers": {"authorization": bearer},
	}).allow == true
}

# The adapter passes no backend configuration: main.rego reads its own.
test_policy_input_has_no_backend_config if {
	policy_input := data.umzh.authz.gateway._policy_input with input as _task_search("")
	not "fhir_base" in object.keys(policy_input)
	not "fhir_authorization" in object.keys(policy_input)
}

# Search with no id → empty resource_id.
test_search_no_id if {
	_main(search_no_id).resource_type == "Task"
	_main(search_no_id).resource_id == ""
}

# --- Token context: exactly one, else "" --------------------------------------
_bearer_with(claims) := {"authorization": sprintf("Bearer %s.%s.sig", [
	base64url.encode_no_pad(`{"alg":"none","typ":"JWT"}`),
	base64url.encode_no_pad(json.marshal(claims)),
])}

_ctx(identifier) := {"type": "http://fhir.ch/ig/ch-umzh-connect/context", "identifier": identifier}

test_one_context_reaches_main if {
	policy_input := data.umzh.authz.gateway._policy_input with input as {"request": {
		"method": "GET", "path": "/fhir/Patient/p1", "query_string": "",
		"headers": _bearer_with({"authorization_details": [_ctx("ServiceRequest/sr1")]}),
	}}
	policy_input.context == "ServiceRequest/sr1"
}

# None or several contexts → "", which main.rego denies for every context-gated read.
test_no_or_several_contexts_become_empty if {
	every details in [[], [_ctx("ServiceRequest/sr1"), _ctx("ServiceRequest/sr2")]] {
		policy_input := data.umzh.authz.gateway._policy_input with input as {"request": {
			"method": "GET", "path": "/fhir/Patient/p1", "query_string": "",
			"headers": _bearer_with({"scope": "system/Patient.r", "authorization_details": details}),
		}}
		policy_input.context == ""
	}
}

# If-Match reaches main.rego as header_if_match, "" when absent.
test_if_match_reaches_main if {
	data.umzh.authz.gateway._policy_input.header_if_match == `W/"3"` with input as {"request": _write(_cancelled, {"if-match": `W/"3"`})}
	data.umzh.authz.gateway._policy_input.header_if_match == "" with input as {"request": _write(_cancelled, {})}
}

# The input is flat: the token's fields sit next to the request's.  No resource
# type, id or read_action: main.rego reads them from the path and the query.
test_policy_input_is_flat if {
	policy_input := data.umzh.authz.gateway._policy_input with input as _task_search("_id=t1")
	object.keys(policy_input) == {
		"method", "path", "query_params", "body",
		"header_if_match", "organization_reference", "scope", "context",
	}
	policy_input.organization_reference == "http://x/Organization/A"
	policy_input.scope == "system/Task.crus"
}

# --- No bearer token: denied explicitly, metadata included ---------------------
test_no_token_denied if {
	every headers in [{}, {"authorization": "Basic dXNlcjpwYXNz"}, {"authorization": "Bearer not-a-jwt"}] {
		data.umzh.authz.gateway.decision == {"allow": false, "status_code": 403} with input as {"request": {
			"method": "GET", "path": "/fhir/metadata", "query_string": "", "headers": headers,
		}}
	}
	data.umzh.authz.gateway.decision == {"allow": true} with input as {"request": {
		"method": "GET", "path": "/fhir/metadata", "query_string": "", "headers": _bearer,
	}}
}

# Without a token the adapter still builds main.rego's input: the denial is the
# explicit token check, not an undefined input.
test_no_token_input_still_built if {
	policy_input := data.umzh.authz.gateway._policy_input with input as search_no_id
	policy_input.organization_reference == ""
	policy_input.scope == ""
}

# A stale If-Match without a token is a 403, not a 412.
test_no_token_no_412 if {
	_real_decision(object.union(object.remove(_write(_cancelled, {}), ["headers"]), {"headers": {"if-match": `W/"2"`}})) == {"allow": false, "status_code": 403}
}

# A request with no method or path still gets an input, and main.rego denies it.
test_missing_method_or_path_denied if {
	every request in [
		{"path": "/fhir/Task", "query_string": "", "headers": _bearer},
		{"method": "GET", "query_string": "", "headers": _bearer},
	] {
		policy_input := data.umzh.authz.gateway._policy_input with input as {"request": request}
		data.umzh.authz.gateway.decision == {"allow": false, "status_code": 403} with input as {"request": request}
	}
}
