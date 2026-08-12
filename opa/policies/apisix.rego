package umzh.authz.apisix

import rego.v1

# ---------------------------------------------------------------------------
# Input shape sent by APISIX's built-in `opa` plugin:
# {
#   "input": {
#     "request": {
#       "method":  "GET",
#       "path":    "/fhir/ServiceRequest",     # no query string
#       "query":   {"_id": "ReferralOrthopedicSurgery"},
#       "headers": {"authorization": "Bearer ...", ...}
#     }
#   }
# }
#
# Party-specific constant (fhir_base) comes from data.config, injected per OPA
# instance via a mounted config JSON.
# ---------------------------------------------------------------------------

# Decode the JWT from the Authorization header (validated by openid-connect before this runs).
# Reading from Authorization (original request) rather than X-Access-Token (set internally
# by openid-connect) avoids APISIX's header-cache staleness — core.request.headers(ctx) is
# snapshot-cached before openid-connect's set_header calls are visible to later plugins.
# io.jwt.decode does NOT verify the signature — validation already happened at the gateway.
jwt_payload := payload if {
	auth := input.request.headers["authorization"]
	startswith(auth, "Bearer ")
	tok := substring(auth, 7, -1)
	[_, payload, _] := io.jwt.decode(tok)
}

# Party config from per-instance data document (opa-config.json).
fhir_base := data.config.fhir_base

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

canonical_path := concat("/", ["/fhir", resource_type, resource_id]) if {
	resource_id != ""
}

canonical_path := input.request.path if {
	resource_id == ""
}

# ---------------------------------------------------------------------------
# Delegate to main.rego with the mapped input shape
# ---------------------------------------------------------------------------
# Authorization is SMART-scope + context (organization_reference / consent /
# fhirContext) centric — every rule in main.rego carries its own scope and
# identity conditions, so there is no coarse realm-role gate here.

allow if {
	# Evaluate existing policy with the input shape it expects.
	data.umzh.authz.allow with input as {
		"method":        input.request.method,
		"path":          canonical_path,
		"resource_type": resource_type,
		"resource_id":   resource_id,
		"token": {
			"organization_reference": object.get(object.get(object.get(jwt_payload, "extensions", {}), "umzhconnect", {}), "organization_reference", ""),
			"scope":                  object.get(jwt_payload, "scope", ""),
			"fhir_context":           object.get(jwt_payload, "fhirContext", []),
		},
		"fhir_base":          fhir_base,
		"fhir_authorization": fhir_authorization,
	}
}
