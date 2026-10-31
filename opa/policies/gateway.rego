package umzh.authz.gateway

import rego.v1

# ---------------------------------------------------------------------------
# Gateway / PEP request adapter. The SAME entrypoint serves every Policy
# Enforcement Point that fronts this node — the APISIX external gateway AND
# external integration platforms (e.g. MuleSoft) reaching OPA through its ingress.
# All of them POST the request they are proxying as `input.request`:
# {
#   "input": {
#     "request": {
#       "method":  "GET",
#       "path":    "/fhir/ServiceRequest",     # no query string
#       "query":   {"_id": "ReferralOrthopedicSurgery"},
#       "headers": {"authorization": "Bearer ..."},  # header name case-insensitive
#       "body":    "{\"resourceType\": \"Task\"}"     # POST/PUT: the raw body, a string
#     }
#   }
# }
#
# Party-specific constant (fhir_base) comes from data.config, injected per OPA
# instance via a mounted config JSON — never from the caller.
#
# ── TRUST MODEL (see BACKLOG.md) ────────────────────────────────────────────
# io.jwt.decode below does NOT verify the JWT signature; it only reads the
# claims. Every consumer MUST authenticate the token BEFORE calling OPA: APISIX
# does it with its openid-connect plugin (JWKS); MuleSoft validates the token in
# its own flow before forwarding. So OPA does authZ on an already-authN'd token.
# Adding OPA-side signature verification (io.jwt.decode_verify vs the auth-server
# JWKS) is a tracked improvement — see BACKLOG.md.
# ---------------------------------------------------------------------------

# A header value, looked up CASE-INSENSITIVELY: APISIX lowercases header names, but
# other consumers (MuleSoft) may send "Authorization".
_header(name) := v if {
	some k, v in input.request.headers
	lower(k) == name
}

# Absent ⇒ jwt_payload stays unset ⇒ default-deny.
_authorization := _header("authorization")

# Decode (NOT verify — see the trust model above) the JWT from the bearer.
jwt_payload := payload if {
	startswith(_authorization, "Bearer ")
	tok := substring(_authorization, 7, -1)
	[_, payload, _] := io.jwt.decode(tok)
}

# Party config. fhir_base normally comes from the per-instance data document
# (opa-config.json). It MAY be overridden by the OPA process ENVIRONMENT
# (opa.runtime().env.FHIR_BASE) so a party can point THIS otherwise-identical
# policy + config bundle at a DIFFERENT (e.g. cluster-external) FHIR backend
# WITHOUT editing the committed opa-config.json. The env wins when set & non-empty;
# otherwise the data document is used. Never sourced from the caller.
fhir_base := base if {
	base := object.get(opa.runtime().env, "FHIR_BASE", "")
	base != ""
} else := data.config.fhir_base

# OPTIONAL Authorization header OPA attaches to its own FHIR fetches (the
# http.send calls in main.rego for Consent/Task/ServiceRequest). Sourced from the
# OPA process ENVIRONMENT (opa.runtime().env), NOT the committed opa-config.json,
# because it is a secret. Empty ⇒ no header (unchanged behaviour). Set it to the
# full header value, e.g. "Basic <base64(user:pass)>", when the FHIR server OPA
# queries requires credentials.
fhir_authorization := object.get(opa.runtime().env, "FHIR_BACKEND_AUTHORIZATION", "")

# ---------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------

# /fhir/<type>  or  /fhir/<type>/<id>  →  ["<type>"] or ["<type>", "<id>"]
_path_parts := split(trim_prefix(input.request.path, "/fhir/"), "/")

resource_type := _path_parts[0]

resource_id := id if {
	count(_path_parts) >= 2
	id := _path_parts[1]
	id != ""
} else := id if {
	id := input.request.query["_id"]
	id != ""
} else := ""

# Every _include value, whatever the modifier. APISIX sends a lone value as a
# string and repeated ones as an array.
_as_array(v) := v if is_array(v)

_as_array(v) := [v] if not is_array(v)

includes := [value |
	some key, raw in input.request.query
	startswith(key, "_include")
	some value in _as_array(raw)
]

# FHIR id syntax. Anything else can mean one resource to OPA's fetch and another
# to HAPI's search.
_valid_id if resource_id == ""

_valid_id if regex.match(`^[A-Za-z0-9.-]{1,64}$`, resource_id)

# The Task _include gate can't see what a PEP doesn't forward. Only a search can
# include anything: HAPI refuses _include on a read.
_query_forwarded if input.request.method != "GET"

_query_forwarded if resource_type != "Task"

_query_forwarded if resource_id != ""

_query_forwarded if is_object(input.request.query)

# POST names the type and PUT one resource, in the path: HAPI ignores If-Match on a
# conditional PUT /Task?_id=<id>, and nothing below a resource is a write target.
_valid_path if input.request.method == "GET"

_valid_path if count(_path_parts) == {"POST": 1, "PUT": 2}[input.request.method]

# The raw body of a write: a string, so nothing reformats it before main.rego compares
# it. Absent or not JSON ⇒ {} ⇒ the write rules deny.
default _body := {}

_body := json.unmarshal(input.request.body)

default _if_match := ""

_if_match := _header("if-match")

# A search needs the s scope, a read the r scope.
default _read_action := "r"

_read_action := "s" if count(_path_parts) == 1

# The token's contexts. Entries of other types are ignored.
_contexts := [entry.identifier |
	some entry in object.get(jwt_payload, "authorization_details", [])
	entry.type == "http://fhir.ch/ig/ch-umzh-connect/context"
]

# Refused here, whatever main.rego decides.
_well_formed if {
	_valid_id
	_valid_path
	_query_forwarded

	# conditionalCreate is false: HAPI would answer with the match, whoever owns it.
	not _header("if-none-exist")
}

# ---------------------------------------------------------------------------
# Delegate to main.rego with the mapped input shape
# ---------------------------------------------------------------------------
# Authorization is SMART-scope + context (organization_reference / consent /
# context graph) centric — every rule in main.rego carries its own scope and
# identity conditions, so there is no coarse realm-role gate here.
#
# `default allow := false` makes the decision an EXPLICIT boolean: a denied query
# returns {"result": false} rather than an undefined {} (which happens when the
# rule body isn't satisfied — e.g. no bearer, or main.rego denied). External
# callers (MuleSoft) can then check `result == false` instead of "result absent".
# The APISIX gateway plugin treats false and absent the same, so this is inert
# for the gateway.
default allow := false

allow if {
	_well_formed

	# Evaluate existing policy with the input shape it expects.
	data.umzh.authz.allow with input as _policy_input
}

# What a consumer answers instead of 403 when allow is false.
default status_code := 403

status_code := 412 if {
	_well_formed
	data.umzh.authz.task_version_mismatch with input as _policy_input
}

# What APISIX queries: the whole package also holds the bearer and the request body.
decision := {"allow": allow, "status_code": status_code}

_policy_input := {
	"method":        input.request.method,
	"path":          input.request.path,
	"resource_type": resource_type,
	"resource_id":   resource_id,
	"includes":      includes,
	"body":          _body,
	"if_match":      _if_match,
	"read_action":   _read_action,
	"token": {
		"organization_reference": object.get(object.get(object.get(jwt_payload, "extensions", {}), "umzhconnect", {}), "organization_reference", ""),
		"scope":                  object.get(jwt_payload, "scope", ""),
		"contexts":               _contexts,
	},
	"fhir_base":          fhir_base,
	"fhir_authorization": fhir_authorization,
}
