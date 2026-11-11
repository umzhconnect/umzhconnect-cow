# =============================================================================
# UMZH Connect - OPA authorization policies (core)
# =============================================================================
# Main policy package for context-centric authorization enforcement.
#
# Authorization model:
# The access token carries the context in its RFC 9396 `authorization_details`
# claim, whose identifier names the workflow root.  The Consent is not named by
# the token; instead OPA locates it by searching
# `Consent?data=ServiceRequest/<id>&status=active` and verifies the actor.
#
# Two workflow-root types are supported (Rule 4 / Rule 4b):
#
# Rule 4 — ServiceRequest-rooted context (fulfiller reading from placer):
#   1. Resolve the context → ServiceRequest/<id>
#   2. Search Consent?data=ServiceRequest/<id>&status=active in this partition
#   3. Verify provision.actor == organization_reference (exact) + not expired
#   4. Fetch the ServiceRequest, require status active, compute its graph
#   5. Permit if the requested resource is in the graph
#
# Rule 4b — Task-rooted context (placer reading Task output from fulfiller):
#   The Task names the counter-party, so no Consent: the caller must be
#   Task.requester.  No status check, and the graph walks
#   Task.output[].valueReference
#
# Rule numbers are kept stable so tests, requests and docs keep their names:
# rules 2 and 6 were removed in #7.
#
# Naming: this package isn't exposed outside the cluster, so it uses no `_`
# prefix.  The backend credential is protected by being read inside a function,
# which OPA's data API never evaluates, not by a name.
# =============================================================================

package umzh.authz

import rego.v1

# ---------------------------------------------------------------------------
# Input structure expected from the gateway/PEP adapter (`gateway.rego`), here for
# GET /fhir/ServiceRequest?_id=ReferralOrthopedicSurgery&_include=...:
# {
#   "method": "GET",
#   "path": "/fhir/ServiceRequest",                 # the resource type, and the id
#                                                   # for a read; see below
#   "query_params": [                               # optional, defaults to []; null
#                                                   # (unparsable) denies a GET search
#     {"_id": "ReferralOrthopedicSurgery"},         # one parameter per entry, in any
#     {"_include": "ServiceRequest:subject"},       # order; a repeated one is several
#     {"_include": "ServiceRequest:requester"},     # entries
#     {"_include:iterate": "PractitionerRole:practitioner"},
#     {"_include:iterate": "DiagnosticReport:result"}
#   ],
#   "body": {},                                     # a write's parsed body
#   "header_if_match": "",                          # the If-Match header, "" if none
#   "organization_reference": "http://localhost:8084/fhir/Organization/HospitalF",
#   "scope": "system/Patient.rs system/ServiceRequest.rs ...",
#   "context": "ServiceRequest/ReferralOrthopedicSurgery"   # the token's one context, "" if none
# }
# The last three come from the token.  The FHIR server OPA reads from, and its
# credential, are never input: see the backend configuration below.
# ---------------------------------------------------------------------------

# Default deny
default allow := false

# A request is allowed when it is admissible and one of the rules below permits it.
allow if {
	admissible
	permitted
}

# What every decision needs, the 412 below included.  No FHIR server configured ⇒
# nothing is allowed, not even the rules that fetch nothing.
admissible if {
	fhir_base != ""
	query_params_usable
	includes_permitted
}

# ==========================================================================
# The request — what it targets, read from the path and the query parameters
# ==========================================================================

# /fhir/<type> names a type, /fhir/<type>/<id> one resource.  Anything deeper (a
# /_history/<n>, an operation) is neither: OPA can't say what it targets, so every
# rule denies it.
path_parts := split(trim_prefix(input.path, "/fhir/"), "/")

type_level if count(path_parts) == 1

instance_level if {
	count(path_parts) == 2
	path_parts[1] != ""
}

resource_type := path_parts[0]

# The id: from the path for a read, from the one _id for a search, else "".
default resource_id := ""

resource_id := path_parts[1] if instance_level

resource_id := id if {
	type_level
	[id] := [value | some param in query_params; some key, value in param; key == "_id"]
}

# The resource this request names, e.g. "Patient/123".
requested_ref := concat("/", [resource_type, resource_id])

# A GET is a search of a type or a read of one resource.  A search needs the s
# scope, a read the r scope.  Method and id can't tell them apart: GET /Task/t1 and
# GET /Task?_id=t1 both name Task/t1.  read_action is undefined for anything else.
get_search if {
	input.method == "GET"
	type_level
}

get_read if {
	input.method == "GET"
	instance_level
}

read_action := "s" if get_search

read_action := "r" if get_read

# The query parameters, [] when the input has none.  The adapter sends null for a
# query string it couldn't parse.
query_params := object.get(input, "query_params", [])

# A GET search's decision depends on its query parameters: _id names the resource,
# and the _include values are checked.  So it needs them as a list of {name: value}
# entries, with at most one _id: the FHIR server ANDs a repeated _id, and OPA would
# have to pick one.  null, the adapter's "couldn't parse", is no list, so it's
# denied rather than read as "no parameters".  A read names its resource in the
# path, and a write's query doesn't decide anything, so neither needs them.
query_params_usable if not get_search

query_params_usable if {
	get_search
	is_array(query_params)
	every param in query_params {
		is_object(param)
	}
	count([param | some param in query_params; "_id" in object.keys(param)]) <= 1
}

# The _include and _include:iterate values among the query parameters.
includes := [value |
	some param in query_params
	some key, value in param
	startswith(key, "_include")
]

# _include and _include:iterate only on a search by _id.  Without one, the search
# could match any number of resources, and the include would pull in what each of
# them references.  A read may not include either.
includes_permitted if count(includes) == 0

includes_permitted if {
	get_search
	resource_id != ""
}

# ==========================================================================
# Backend configuration — this OPA instance's own, never the caller's
# ==========================================================================

# The FHIR server OPA reads Consent / Task / ServiceRequest from.  The per-instance
# data document (opa-config.json) sets it.  A non-empty FHIR_BASE in the OPA
# process environment overrides it, so a party can point the same policies and
# config at another (e.g. cluster-external) backend without editing that file.
fhir_base := base if {
	base := object.get(opa.runtime().env, "FHIR_BASE", "")
	base != ""
} else := data.config.fhir_base

# A GET on the FHIR server.  It carries Authorization when FHIR_BACKEND_AUTHORIZATION
# is set in the OPA process environment, e.g. "Basic <base64(user:pass)>"; unset or
# empty ⇒ no header.  The credential is a secret, so it's read here and only here:
# OPA's data API returns the value of every rule, but never of a function.
fhir_get(url) := {
	"method": "GET",
	"url": url,
	"headers": object.union({"Accept": "application/fhir+json"}, backend_authorization(url)),
	"force_json_decode": true,
}

backend_authorization(_) := {"Authorization": auth} if {
	auth := object.get(opa.runtime().env, "FHIR_BACKEND_AUTHORIZATION", "")
	auth != ""
} else := {}

# ==========================================================================
# Rule 1a: Task search — require system/Task.s
# ------------------------------------------------------------------------
# The API gateway also adds requester=<organization_reference> to the query it
# forwards, so the FHIR server returns only Tasks where the caller is the named
# requester. The scope check here gates *whether* the search may run; the
# requester filter scopes *what it returns*.
#
# organization_reference must be non-empty: the requester filter is the ONLY
# thing scoping a Task search to the caller, and a gateway with no value to add
# would let the FHIR server return every Task in the partition. Fail closed
# rather than rely on that downstream filter.
# ==========================================================================
permitted if {
	resource_type == "Task"
	get_search
	resource_id == ""
	input.organization_reference != ""
	has_smart_scope("Task", "s")
}

# ==========================================================================
# Rule 1b: Task read by id — require system/Task.r AND the fetched Task's
# requester field must equal the calling party's organization_reference.
# Also serves GET /Task?_id=<id>, which needs system/Task.s instead, and where
# an _include may need a Task context.
# ==========================================================================
permitted if {
	resource_type == "Task"
	resource_id != ""
	has_smart_scope("Task", read_action)
	task := fetched_resource(requested_ref)
	task.requester.reference == input.organization_reference
	task_include_permitted
}

# ==========================================================================
# Rule 1c: Task create (POST) — the caller must be Task.requester, which rules
# 1b, 1d and 4b trust.  No Task.output or businessStatus: only the Fulfiller sets
# them, and rules 4b and 1d trust them too.  HAPI stores an object sent as _output
# or _businessStatus in the plain field.
# ==========================================================================
permitted if {
	input.method == "POST"
	type_level
	resource_type == "Task"
	has_smart_scope("Task", "c")
	input.organization_reference != ""
	input.body.requester.reference == input.organization_reference
	count(object.keys(input.body) & {"output", "_output", "businessStatus", "_businessStatus"}) == 0
}

# ==========================================================================
# Rule 1d: Task update (PUT) — the caller must be Task.requester, If-Match must
# name the version read here, and the change must be one the Placer may make.
# HAPI gets the same If-Match, so the Task can't change between this check and
# the write.  An unknown id fails the read, so PUT can't create a Task.
# ==========================================================================
permitted if {
	input.header_if_match == task_etag(updatable_task)
	task_update_permitted(updatable_task, input.body)
}

# ==========================================================================
# Rule 3: Allow Questionnaire reads and searches
# ==========================================================================
permitted if {
	resource_type == "Questionnaire"
	has_smart_scope("Questionnaire", read_action)
}

# ==========================================================================
# Rule 4: Allow read of resources within the ServiceRequest context graph
# ==========================================================================
permitted if {
	resource_type != "Task"
	# A blank _id arrives as "", and HAPI would then return every resource.
	resource_id != ""
	has_smart_scope(resource_type, read_action)
	sr_ref := context_sr_ref
	consent_grants(sr_ref)
	fetched_resource(sr_ref).status == "active"
	resource_in_graph(sr_ref)
}

# ==========================================================================
# Rule 4b: Allow read of resources within the Task context graph
# ==========================================================================
permitted if {
	resource_type != "Task"
	resource_id != ""
	has_smart_scope(resource_type, read_action)
	task_ref := context_task_ref
	fetched_resource(task_ref).requester.reference == input.organization_reference
	resource_in_task_graph(task_ref)
}

# ==========================================================================
# Rule 5: Allow the CapabilityStatement (GET /fhir/metadata), whatever the scope.
# Through the adapter it still needs a bearer token, like every request.
# ==========================================================================
permitted if {
	input.path == "/fhir/metadata"
	get_search
}

# ==========================================================================
# Context resolution
# ==========================================================================

# The token's one context.  The adapter sends "" when the token has none or several,
# and "" matches neither pattern, which denies every context-gated request.
# Anchored: a /_history/<n> suffix would make the fetches read an old version.
context_sr_ref := input.context if regex.match(`^ServiceRequest/[A-Za-z0-9.-]{1,64}$`, input.context)

context_task_ref := input.context if regex.match(`^Task/[A-Za-z0-9.-]{1,64}$`, input.context)

# ==========================================================================
# Task _include — what it pulls in is context-gated, the Task itself is not
# ==========================================================================

# Task:output-value-canonical is exempt: it lists Questionnaires, and only the
# Fulfiller writes Task.output.
task_include_needs_context if {
	some value in includes
	value != "Task:output-value-canonical"
}

task_include_permitted if not task_include_needs_context

task_include_permitted if requested_ref == context_task_ref

# ==========================================================================
# Task update — the IG's two changes a Placer may make
# ==========================================================================

updatable_task := task if {
	input.method == "PUT"
	instance_level
	resource_type == "Task"
	has_smart_scope("Task", "u")
	task := fetched_resource(requested_ref)
	task.requester.reference == input.organization_reference
}

task_etag(task) := sprintf(`W/"%s"`, [task.meta.versionId])

# A missing or stale If-Match: the adapter turns this denial into a 412.
task_version_mismatch if {
	admissible
	input.header_if_match != task_etag(updatable_task)
}

# The top-level fields that differ.  The IG leaves out meta, text and lastModified.
task_changes(stored, submitted) := {field |
	some field in (object.keys(stored) | object.keys(submitted))
	not field in {"meta", "text", "lastModified"}
	object.get(stored, field, null) != object.get(submitted, field, null)
}

# Cancel before work starts.  A statusReason may be added, not changed.
task_update_permitted(stored, submitted) if {
	stored.status in {"requested", "accepted"}
	submitted.status == "cancelled"
	task_changes(stored, submitted) - ({"statusReason"} - object.keys(stored)) == {"status"}
}

# Answer a request for information: add to Task.input and clear businessStatus.
task_update_permitted(stored, submitted) if {
	some coding in stored.businessStatus.coding
	coding.code == "awaiting-information"
	task_changes(stored, submitted) == {"input", "businessStatus"}
	not submitted.businessStatus
	is_array(submitted.input)
	stored_input := object.get(stored, "input", [])
	every entry in stored_input {
		entry in submitted.input
	}
	count(submitted.input) > count(stored_input)
}

# ==========================================================================
# Consent resolution — search by the context's ServiceRequest
# ==========================================================================

# Search for active Consents whose provision.data references <sr_ref>.
# Not cached: the Consent must be re-read live on every request so that
# revocation (status=inactive) and expiry take effect immediately.
consent_search(sr_ref) := resp if {
	resp := http.send(fhir_get(sprintf("%s/Consent?data=%s&status=active", [fhir_base, sr_ref])))
	resp.status_code == 200
}

# Normalise a FHIR date ("2026-06-15") or datetime ("2026-06-15T00:00:00Z") to
# nanoseconds since epoch.  date.parse_rfc3339_ns requires a full RFC3339 string.
to_ns(s) := t if {
	contains(s, "T")
	t := time.parse_rfc3339_ns(s)
}

to_ns(s) := t if {
	not contains(s, "T")
	t := time.parse_rfc3339_ns(concat("", [s, "T00:00:00Z"]))
}

# Expiry test for a Consent.
# A missing provision.period.end means the Consent is open-ended (never
# expires) — only an end value that has actually passed makes it expired.
consent_not_expired(consent) if {
	not consent.provision.period.end
}

consent_not_expired(consent) if {
	# Handles both date-only ("2026-06-15") and full RFC3339 end values.
	time.now_ns() < to_ns(consent.provision.period.end)
}

# ==========================================================================
# Helper: an active, non-expired Consent issued to this party covers <sr_ref>
# ==========================================================================
consent_grants(sr_ref) if {
	resp := consent_search(sr_ref)
	some entry in resp.body.entry
	consent := entry.resource
	consent.status == "active"
	# Exact match: organization_reference must equal the actor's full Registry URL
	some actor in consent.provision.actor
	actor.reference.reference == input.organization_reference
	consent_not_expired(consent)
}

# ==========================================================================
# ServiceRequest graph — derive resource scope from a ServiceRequest context
# ==========================================================================

# Fetch <ref> from this party's partition.  Not cached: Task state,
# ServiceRequest.status and QuestionnaireResponse.basedOn all decide access.
fetched_resource(ref) := resource if {
	resp := http.send(fhir_get(concat("/", [fhir_base, ref])))
	resp.status_code == 200
	resource := resp.body
}

# The set of resource references reachable from ServiceRequest <sr_ref>: the SR
# itself plus everything its subject, requester, reasonReference, supportingInfo
# and insurance fields point to.  performer is intentionally excluded — it is the
# receiving organisation.
service_request_graph(sr_ref) := graph if {
	sr := fetched_resource(sr_ref)
	graph := (
		{sr_ref} |
		{ref | ref := sr.subject.reference} |
		{ref | ref := sr.requester.reference} |
		{ref | some item in sr.reasonReference;  ref := item.reference} |
		{ref | some item in sr.supportingInfo;   ref := item.reference} |
		{ref | some item in sr.insurance;        ref := item.reference}
	)
}

# ==========================================================================
# Helper: the requested resource lies within ServiceRequest <sr_ref>'s graph
# ==========================================================================
resource_in_graph(sr_ref) if {
	some ref in service_request_graph(sr_ref)
	# endswith handles both relative ("Patient/X") and absolute URL references
	endswith(ref, requested_ref)
}

# QuestionnaireResponse.basedOn is the one back-reference the IG admits.  Exact
# match: both resources live on this server, so an absolute URL may name another.
resource_in_graph(sr_ref) if {
	resource_type == "QuestionnaireResponse"
	some based_on in fetched_resource(requested_ref).basedOn
	based_on.reference == sr_ref
}

# ==========================================================================
# Task graph — derive resource scope from a Task context
# ==========================================================================

# The set of resource references reachable from Task <task_ref>: the Task
# itself plus everything its output[].valueReference fields point to.  Not
# Task.input: the Placer fills it, so it must not decide what the Placer can read.
task_graph(task_ref) := graph if {
	task := fetched_resource(task_ref)
	graph := (
		{task_ref} |
		{ref | some item in task.output; ref := item.valueReference.reference}
	)
}

# ==========================================================================
# Helper: the requested resource lies within Task <task_ref>'s graph
# ==========================================================================
resource_in_task_graph(task_ref) if {
	some ref in task_graph(task_ref)
	endswith(ref, requested_ref)
}

# ==========================================================================
# Helper: Check if token carries the required SMART on FHIR scope
# ==========================================================================
has_smart_scope(resource, action) if {
	some scope in split(input.scope, " ")
	parts := split(scope, "/")
	count(parts) == 2
	ra := split(parts[1], ".")
	ra[0] == resource
	contains(ra[1], action)
}
