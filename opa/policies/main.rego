# =============================================================================
# UMZH Connect Sandbox - OPA Authorization Policies
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
#   3. Verify provision.actor == token.organization_reference (exact) + not expired
#   4. Fetch the ServiceRequest, require status active, compute its graph
#   5. Permit if the requested resource is in the graph
#
# Rule 4b — Task-rooted context (placer reading Task output from fulfiller):
#   The Task names the counter-party, so no Consent: the caller must be
#   Task.requester.  No status check, and the graph walks
#   Task.output[].valueReference
# =============================================================================

package umzh.authz

import rego.v1

# Default deny
default allow := false

# ---------------------------------------------------------------------------
# Input structure expected from the gateway/PEP adapter (`gateway.rego`):
# {
#   "method": "GET",
#   "path": "/fhir/Patient/123",
#   "resource_type": "Patient",
#   "resource_id": "123",
#   "includes": [],
#   "body": {},
#   "if_match": "",
#   "read_action": "r",
#   "token": {
#     "organization_reference": "http://localhost:8084/fhir/Organization/HospitalF",
#     "scope":                  "system/Patient.rs system/Task.crus ...",
#     "contexts":               ["ServiceRequest/sr-123"]
#   },
#   "fhir_base": "http://nginx-proxy:81/fhir/placer"
# }
# ---------------------------------------------------------------------------

# ==========================================================================
# Rule 1a: Task search — require system/Task.s
# ------------------------------------------------------------------------
# The gateway also injects ?requester=<organization_reference> via the
# umzh-task-requester-inject plugin so HAPI returns only Tasks where the
# caller is the named requester. The scope check here gates *whether* the
# search may run; the requester filter scopes *what it returns*.
#
# organization_reference must be non-empty: the requester filter is the ONLY
# thing scoping a Task search to the caller, and umzh-task-requester-inject
# silently no-ops when the value is absent — which would let HAPI return every
# Task in the partition. Fail closed rather than rely on that downstream filter.
# ==========================================================================
allow if {
	input.resource_type == "Task"
	input.method == "GET"
	input.resource_id == ""
	input.token.organization_reference != ""
	has_smart_scope("Task", "s")
	not task_include_needs_context
}

# ==========================================================================
# Rule 1b: Task read by id — require system/Task.r AND the fetched Task's
# requester field must equal the calling party's organization_reference.
# Also serves GET /Task?_id=<id>, which needs system/Task.s instead, and where
# an _include may need a Task context.
# ==========================================================================
allow if {
	input.resource_type == "Task"
	input.method == "GET"
	input.resource_id != ""
	has_smart_scope("Task", input.read_action)
	task := fetched_resource(requested_ref)
	task.requester.reference == input.token.organization_reference
	task_include_permitted
}

# ==========================================================================
# Rule 1c: Task create (POST) — the caller must be Task.requester, which rules
# 1b, 1d and 4b trust.  No Task.output or businessStatus: only the Fulfiller sets
# them, and rules 4b and 1d trust them too.  HAPI stores an object sent as _output
# or _businessStatus in the plain field.
# ==========================================================================
allow if {
	input.resource_type == "Task"
	input.method == "POST"
	has_smart_scope("Task", "c")
	input.token.organization_reference != ""
	input.body.requester.reference == input.token.organization_reference
	count(object.keys(input.body) & {"output", "_output", "businessStatus", "_businessStatus"}) == 0
}

# ==========================================================================
# Rule 1d: Task update (PUT) — the caller must be Task.requester, If-Match must
# name the version read here, and the change must be one the Placer may make.
# HAPI gets the same If-Match, so the Task can't change between this check and
# the write.  An unknown id fails the read, so PUT can't create a Task.
# ==========================================================================
allow if {
	input.if_match == task_etag(updatable_task)
	task_update_permitted(updatable_task, input.body)
}

# ==========================================================================
# Rule 3: Allow Questionnaire read operations
# ==========================================================================
allow if {
	input.resource_type == "Questionnaire"
	input.method == "GET"
	has_smart_scope("Questionnaire", input.read_action)
}

# ==========================================================================
# Rule 4: Allow read of resources within the ServiceRequest context graph
# ==========================================================================
allow if {
	input.method == "GET"
	input.resource_type != "Task"
	# A blank _id arrives as "", and HAPI would then return every resource.
	input.resource_id != ""
	has_smart_scope(input.resource_type, input.read_action)
	sr_ref := context_sr_ref
	consent_grants(sr_ref)
	fetched_resource(sr_ref).status == "active"
	resource_in_graph(sr_ref)
}

# ==========================================================================
# Rule 4b: Allow read of resources within the Task context graph
# ==========================================================================
allow if {
	input.method == "GET"
	input.resource_type != "Task"
	input.resource_id != ""
	has_smart_scope(input.resource_type, input.read_action)
	task_ref := context_task_ref
	fetched_resource(task_ref).requester.reference == input.token.organization_reference
	resource_in_task_graph(task_ref)
}

# ==========================================================================
# Rule 5: Allow metadata endpoint always
# ==========================================================================
allow if {
	input.path == "/fhir/metadata"
}

# ==========================================================================
# Context resolution
# ==========================================================================

# The token's one context.  None or several leaves it undefined, which denies
# every context-gated request.
context_ref := input.token.contexts[0] if count(input.token.contexts) == 1

# Anchored: a /_history/<n> suffix would make the fetches read an old version.
context_sr_ref := context_ref if regex.match(`^ServiceRequest/[A-Za-z0-9.-]{1,64}$`, context_ref)

context_task_ref := context_ref if regex.match(`^Task/[A-Za-z0-9.-]{1,64}$`, context_ref)

# ==========================================================================
# Task _include — what it pulls in is context-gated, the Task itself is not
# ==========================================================================

# Task:output-value-canonical is exempt: it lists Questionnaires, and only the
# Fulfiller writes Task.output.
task_include_needs_context if {
	some value in input.includes
	value != "Task:output-value-canonical"
}

task_include_permitted if not task_include_needs_context

task_include_permitted if requested_ref == context_task_ref

# ==========================================================================
# Task update — the IG's two changes a Placer may make
# ==========================================================================

updatable_task := task if {
	input.resource_type == "Task"
	input.method == "PUT"
	has_smart_scope("Task", "u")
	task := fetched_resource(requested_ref)
	task.requester.reference == input.token.organization_reference
}

task_etag(task) := sprintf(`W/"%s"`, [task.meta.versionId])

# A missing or stale If-Match: the adapter turns this denial into a 412.
task_version_mismatch if input.if_match != task_etag(updatable_task)

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

# Headers OPA sends on its FHIR fetches. Always Accept JSON; additionally carry
# Authorization when the FHIR server requires it — input.fhir_authorization is the
# full header value, injected by the adapter (gateway.rego) from the OPA
# environment. Empty/absent ⇒ Accept-only, unchanged behaviour.
_fhir_headers := {"Accept": "application/fhir+json", "Authorization": auth} if {
	auth := object.get(input, "fhir_authorization", "")
	auth != ""
} else := {"Accept": "application/fhir+json"}

# Search for active Consents whose provision.data references <sr_ref>.
# Not cached: the Consent must be re-read live on every request so that
# revocation (status=inactive) and expiry take effect immediately.
consent_search(sr_ref) := resp if {
	url := sprintf("%s/Consent?data=%s&status=active", [input.fhir_base, sr_ref])
	resp := http.send({
		"method":            "GET",
		"url":               url,
		"headers":           _fhir_headers,
		"force_json_decode": true,
	})
	resp.status_code == 200
}

# Normalise a FHIR date ("2026-06-15") or datetime ("2026-06-15T00:00:00Z") to
# nanoseconds since epoch.  date.parse_rfc3339_ns requires a full RFC3339 string.
_to_ns(s) := t if {
	contains(s, "T")
	t := time.parse_rfc3339_ns(s)
}

_to_ns(s) := t if {
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
	time.now_ns() < _to_ns(consent.provision.period.end)
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
	actor.reference.reference == input.token.organization_reference
	consent_not_expired(consent)
}

# ==========================================================================
# ServiceRequest graph — derive resource scope from a ServiceRequest context
# ==========================================================================

# The resource this request names, e.g. "Patient/123".
requested_ref := concat("/", [input.resource_type, input.resource_id])

# Fetch <ref> from this party's partition.  Not cached: Task state,
# ServiceRequest.status and QuestionnaireResponse.basedOn all decide access.
fetched_resource(ref) := resource if {
	url := concat("/", [input.fhir_base, ref])
	resp := http.send({
		"method":            "GET",
		"url":               url,
		"headers":           _fhir_headers,
		"force_json_decode": true,
	})
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
	input.resource_type == "QuestionnaireResponse"
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
	some scope in split(input.token.scope, " ")
	parts := split(scope, "/")
	count(parts) == 2
	ra := split(parts[1], ".")
	ra[0] == resource
	contains(ra[1], action)
}
