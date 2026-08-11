# =============================================================================
# adapter_test.rego — unit tests for the APISIX request adapter in
# opa/policies/apisix.rego (package umzh.authz.apisix): path/query → the
# resource_type / resource_id / canonical_path it hands to main.rego. Pure (no
# http.send), so no mocks needed.
# =============================================================================
package umzh.authz.apisix_test

import rego.v1

read_by_id := {"request": {"path": "/fhir/Patient/123", "query": {}, "headers": {}}}

search_with_id := {"request": {"path": "/fhir/ServiceRequest", "query": {"_id": "abc"}, "headers": {}}}

search_no_id := {"request": {"path": "/fhir/Task", "query": {}, "headers": {}}}

# Read by id → type + id come from the path.
test_read_by_id_type if {
	data.umzh.authz.apisix.resource_type == "Patient" with input as read_by_id
}

test_read_by_id_id if {
	data.umzh.authz.apisix.resource_id == "123" with input as read_by_id
}

test_read_by_id_canonical if {
	data.umzh.authz.apisix.canonical_path == "/fhir/Patient/123" with input as read_by_id
}

# Search with _id → id comes from the query, canonical_path folds it in.
test_search_with_id_type if {
	data.umzh.authz.apisix.resource_type == "ServiceRequest" with input as search_with_id
}

test_search_with_id_id if {
	data.umzh.authz.apisix.resource_id == "abc" with input as search_with_id
}

test_search_with_id_canonical if {
	data.umzh.authz.apisix.canonical_path == "/fhir/ServiceRequest/abc" with input as search_with_id
}

# Search with no id → empty resource_id, canonical_path is the raw path.
test_search_no_id_type if {
	data.umzh.authz.apisix.resource_type == "Task" with input as search_no_id
}

test_search_no_id_empty_id if {
	data.umzh.authz.apisix.resource_id == "" with input as search_no_id
}

test_search_no_id_canonical if {
	data.umzh.authz.apisix.canonical_path == "/fhir/Task" with input as search_no_id
}
