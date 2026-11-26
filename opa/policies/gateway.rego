package umzh.authz.gateway

import rego.v1

# ---------------------------------------------------------------------------
# Gateway / PEP request adapter. The SAME entrypoint serves every API gateway acting
# as Policy Enforcement Point (PEP) in front of this node, whether it calls OPA
# in-cluster or through its ingress. Each POSTs the request it is proxying as
# `input.request`:
# {
#   "input": {
#     "request": {
#       "method":  "GET",
#       "path":    "/fhir/ServiceRequest",     # no query string
#       # The raw query string, undecoded, exactly as forwarded to the FHIR server;
#       # "" if there is none.  OPA parses it itself.
#       "query_string": "_id=ReferralOrthopedicSurgery&_include=ServiceRequest:subject&_include=ServiceRequest:requester&_include:iterate=PractitionerRole:practitioner&_include:iterate=DiagnosticReport:result",
#       "headers": {"authorization": "Bearer ..."},  # header name case-insensitive
#       "body":    "{\"resourceType\": \"Task\"}"     # POST/PUT: the raw body as a string,
#                                                    # or the same JSON as an object
#     }
#   }
# }
#
# This package only maps the request into main.rego's input. What the request
# targets, and the FHIR server OPA reads from, are main.rego's to work out.
#
# Naming: the ingress publishes this package, so only its entrypoints — `decision`,
# `allow` and `status_code` — are public.  Everything else is `_`-prefixed.
#
# ── RESPONSIBILITIES (see BACKLOG.md) ───────────────────────────────────────
# The API gateway in front of OPA (such as APISIX, MuleSoft or Kong) and OPA split
# the work. OPA authorizes; it relies on the gateway for everything below and does
# not check it again.
#
# The API gateway is responsible for:
#   - Authentication. It validates the bearer token (signature, issuer, expiry)
#     BEFORE calling OPA. _claims below does NOT verify the signature; it only
#     reads the claims, so OPA decides on an already-authenticated token.
#     OPA-side signature verification is a tracked improvement — see BACKLOG.md.
#   - Allowlists. Only the operations, header parameters and query parameters the
#     IG offers pass, everything else is refused: per route, the permitted methods
#     and paths, query parameter names, _include and _include:iterate values, and
#     headers. For example, an If-None-Exist header is refused (conditionalCreate
#     is false), and so is any write but POST /fhir/Task or PUT /fhir/Task/<id>.
#   - Sanity checks on header and query parameter values and on the body. For
#     example, a resource id, in the path or in _id, matches FHIR id syntax
#     ^[A-Za-z0-9.-]{1,64}$ (OPA builds its fetch URL from it), _id is
#     single-valued, each header name appears once, and a write's body is valid
#     application/fhir+json with no duplicate keys (OPA and the FHIR server could
#     each keep a different one of the values).
#   - Scoping a Task search to the caller. On GET /fhir/Task it sets
#     requester=<the token's organization_reference> on the query it forwards to
#     the FHIR server, replacing any requester the client sent. OPA only decides
#     whether the search may run; without this, it returns every Task.
#   - Forwarding to OPA exactly what it forwards to the FHIR server: the raw query
#     string ("" if none) byte for byte, the If-Match header and the body (as the
#     raw string or as the same JSON object). OPA
#     reads _id and the _include values from that query string, and its decision
#     only holds for what it was sent. (The requester filter above is the one
#     addition, made after OPA's decision.)
#
# OPA is responsible for:
#   - The authorization decision: SMART scopes, the caller's organization, the
#     token's context and the Consent / context graph (main.rego).
#   - Interpreting the request it is sent, and denying what it can't interpret: a
#     request without a bearer token, a path deeper than /fhir/<type>/<id>, and a
#     GET search whose query string is missing or malformed, or names _id more
#     than once.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Entrypoints
# ---------------------------------------------------------------------------

# What every API gateway queries: {"allow": true}, or {"allow": false,
# "status_code": 403 | 412}.
decision := {"allow": true} if allow

decision := {"allow": false, "status_code": status_code} if not allow

# `default allow := false` makes `allow` an EXPLICIT boolean: a denied query returns
# {"result": false} rather than an undefined {}.
default allow := false

allow if {
	_token_present
	data.umzh.authz.allow with input as _policy_input
}

# What a consumer answers instead of 403 when allow is false.
default status_code := 403

status_code := 412 if {
	_token_present
	data.umzh.authz.task_version_mismatch with input as _policy_input
}

# ---------------------------------------------------------------------------
# The token
# ---------------------------------------------------------------------------

# A header value, looked up CASE-INSENSITIVELY: gateways differ in how they case
# header names ("authorization" or "Authorization").
_header(name) := v if {
	some k, v in input.request.headers
	lower(k) == name
}

# Decode (NOT verify — see the responsibilities above) the JWT from the bearer.
_decoded := payload if {
	startswith(_header("authorization"), "Bearer ")
	[_, payload, _] := io.jwt.decode(substring(_header("authorization"), 7, -1))
}

# No bearer token, or one that doesn't decode, is denied: every request needs one,
# /fhir/metadata included.
_token_present if is_object(_decoded)

default _claims := {}

_claims := _decoded

# The token's contexts. Entries of other types are ignored.
_contexts := [entry.identifier |
	some entry in object.get(_claims, "authorization_details", [])
	entry.type == "http://fhir.ch/ig/ch-umzh-connect/context"
]

# A token names exactly one context.  None or several ⇒ "", which main.rego denies
# for every context-gated request.
default _context := ""

_context := _contexts[0] if count(_contexts) == 1

# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------

# The query, parsed here from the raw string: every value is an array, and a
# repeated parameter keeps all its values.  Missing, not a string, or malformed
# (bad percent-encoding, `;` as a separator) ⇒ undefined.
_query := urlquery.decode_object(input.request.query_string) if is_string(input.request.query_string)

# Every query parameter as its own {name: value} entry: a repeated one is several
# entries.  null when the query didn't parse: main.rego then denies a GET search,
# which depends on them, rather than read it as "no parameters".
default _query_params := null

_query_params := [{key: value} |
	some key, values in _query
	some value in values
] if is_object(_query)

# The body of a write, in either form: the raw string the gateway forwards to the
# FHIR server, or that same JSON as an object.  The gateway has already refused
# anything but valid application/fhir+json.  Absent, or a string that isn't JSON
# ⇒ {} ⇒ the write rules deny.
default _body := {}

_body := input.request.body if is_object(input.request.body)

_body := json.unmarshal(input.request.body) if is_string(input.request.body)

default _if_match := ""

_if_match := _header("if-match")

# ---------------------------------------------------------------------------
# main.rego's input
# ---------------------------------------------------------------------------
# Always built, whatever is missing: a missing method or path becomes "", which no
# rule in main.rego permits.  Denials are main.rego's explicit decisions, never an
# input that came out undefined.
_policy_input := {
	"method":          object.get(input.request, "method", ""),
	"path":            object.get(input.request, "path", ""),
	"query_params":    _query_params,
	"body":            _body,
	"header_if_match": _if_match,

	# From the token.
	"organization_reference": object.get(object.get(object.get(_claims, "extensions", {}), "umzhconnect", {}), "organization_reference", ""),
	"scope":                  object.get(_claims, "scope", ""),
	"context":                _context,
}
