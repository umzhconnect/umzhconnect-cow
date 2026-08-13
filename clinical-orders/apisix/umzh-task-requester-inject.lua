-- umzh-task-requester-inject.lua
-- Injects a `requester=<organization_reference>` FHIR search parameter into the
-- upstream request, populated from the caller's JWT claim
-- $.extensions.umzhconnect.organization_reference. That claim is an absolute
-- Registry URL (e.g. https://registry.umzhconnect.ch/fhir/Organization/HospitalP)
-- — the same form stored in Task.requester.reference — so HAPI's exact-match
-- reference search filters correctly.
--
-- Mounted on the external gateway's /fhir/Task list route so HAPI returns only
-- Tasks for which the calling party is named as the requester. Combined with the
-- OPA scope check on the same route (require system/Task.s), this gives:
--   * scope-gated:   caller must hold .s permission
--   * server-side filtered: caller cannot see Tasks belonging to other requesters
--
-- umzhconnect-cow variant (diverges from the sandbox original): this route
-- carries NO proxy-rewrite — partition mapping (/fhir/… → /fhir/clinical-orders/…)
-- is done downstream by the clinical-orders-fhir proxy. Because the requester is
-- a query parameter (not a path segment), we set it via ngx.req.set_uri_args,
-- which APISIX forwards upstream when no proxy-rewrite has rebuilt the upstream
-- URI. Assigning the `requester` key OVERWRITES any caller-supplied value, so the
-- filter cannot be widened. (The sandbox appended to ctx.var.upstream_uri because
-- a proxy-rewrite there had already rebuilt the upstream URI, discarding inbound
-- arg mutations; there is no such rewrite here.)
--
-- The JWT signature is verified by the `openid-connect` plugin on the same route
-- (access phase, priority 2599). This plugin runs later in the access phase
-- (priority 999), so by the time it executes the bearer has already been
-- validated (and OPA, priority 2001, has already required org_ref to be present).
--
-- io.jwt.decode is not used here because resty.jwt's dependency chain is heavy
-- for what is a parse-only operation. The signed JWT's middle segment is
-- base64url-decoded inline; we trust the signature check done upstream.

local plugin_name = "umzh-task-requester-inject"
local cjson = require("cjson.safe")

local _M = {
  version  = 0.1,
  priority = 999,
  name     = plugin_name,
  schema   = { type = "object", properties = {} },
}

local function b64url_decode(s)
  s = s:gsub("-", "+"):gsub("_", "/")
  local rem = #s % 4
  if rem > 0 then s = s .. string.rep("=", 4 - rem) end
  return ngx.decode_base64(s)
end

function _M.access(conf, ctx)
  local auth = ngx.req.get_headers()["authorization"] or ""
  local tok  = auth:match("^Bearer%s+(.+)$")
  if not tok then return end

  local _, payload_b64 = tok:match("([^%.]+)%.([^%.]+)")
  if not payload_b64 then return end

  local payload_json = b64url_decode(payload_b64)
  if not payload_json then return end

  local payload = cjson.decode(payload_json)
  if not payload then return end

  local ext = payload.extensions
  local umzh = ext and ext.umzhconnect
  local org_ref = umzh and umzh.organization_reference
  if not org_ref or org_ref == "" then return end

  -- No proxy-rewrite runs on this route, so APISIX forwards the request's own
  -- URI args upstream. Overwrite (not append) `requester` so a caller cannot
  -- supply their own value to broaden the search; set_uri_args re-encodes the
  -- absolute Registry URL for the query string.
  local args = ngx.req.get_uri_args()
  args.requester = org_ref
  ngx.req.set_uri_args(args)
end

return _M
