-- umzh-capability-guard.lua
-- Deny-by-default allowlist for FHIR query parameters and `_include` values,
-- enforcing the *static* API contract from the IG CapabilityStatement at the
-- edge. It complements the other two layers:
--   * routing      → which (method × resourceType) is reachable at all
--                    (a type with no route → 404, APISIX default-deny).
--   * THIS plugin  → which query params / _include values are permitted on a
--                    route that IS reachable.
--   * OPA          → consent / fhirContext-graph / _id-in-context authorization.
--
-- A request passes only if EVERY query key is explicitly permitted, after
-- normalizing for FHIR parameter syntax:
--   * every name in `require` is present
--   * `_id` (when allowed) is single-valued (no comma-OR, no repeats)
--   * `_include` values ∈ allow_includes  (rejects `*`, unknowns)
--   * `_include:iterate` values ∈ allow_include_iterates (rejects `*`, unknowns;
--     the only `:modifier` accepted on any key)
--   * every other key's BASE name ∈ allow_params, with NO `:modifier` and NO
--     `.chain`
--
-- Deny-by-default means nothing needs an explicit blocklist: `_revinclude`,
-- `_has`, `_filter`, `_query`, `_contained`, `_content`, `_text`, `_list`,
-- modifiers, chained params, and generic control params (`_format`, `_count`,
-- ...) are all rejected simply by not appearing in `allow_params`/`allow_includes`.
--
-- Violations return 400 + an OperationOutcome (FHIR's `handling=strict`
-- behaviour for unsupported parameters; matches what HAPI itself returns). The
-- exact status code is intentionally simple here and may be revisited.

local core = require("apisix.core")
local opa_helper = require("apisix.plugins.opa.helper")

-- A FHIR Task is far smaller; a larger body stays unread and OPA denies the write.
local MAX_BODY_BYTES = 1048576

local schema = {
  type = "object",
  properties = {
    -- Search parameter names that MUST be present (e.g. ["_id"]).
    ["require"]    = { type = "array", items = { type = "string" }, default = {} },
    -- Search parameter names that MAY be present (must include anything in
    -- `require`). Empty ⇒ no query parameters permitted (e.g. read-by-id).
    allow_params   = { type = "array", items = { type = "string" }, default = {} },
    -- Permitted `_include` values, verbatim (e.g. "ServiceRequest:patient").
    allow_includes = { type = "array", items = { type = "string" }, default = {} },
    -- Permitted `_include:iterate` values, verbatim (e.g. "DiagnosticReport:result").
    -- A separate list from allow_includes: a value permitted as a direct include
    -- is NOT thereby permitted to iterate, and vice versa. Empty ⇒ every
    -- `_include:iterate` is rejected.
    allow_include_iterates = { type = "array", items = { type = "string" }, default = {} },
    -- Send the raw request body to OPA on this route.
    forward_body   = { type = "boolean", default = false },
  },
  -- Reject unknown keys at config-load time. Without this a typo fails open in
  -- one case: misspelling `require` (e.g. `requires`) would silently drop the
  -- mandatory-parameter check, letting an unbounded search through.
  additionalProperties = false,
}

local _M = {
  version  = 0.1,
  -- After openid-connect (2599) so auth is checked first; before the opa
  -- plugin (2001) so malformed requests fail fast without a consent lookup.
  priority = 2400,
  name     = "umzh-capability-guard",
  schema   = schema,
}

function _M.check_schema(conf)
  return core.schema.check(schema, conf)
end

-- The stock opa plugin builds its input here and has no option for the body. If an
-- upgrade stops calling this, OPA gets no body and denies every write.
local build_opa_input = opa_helper.build_opa_input

function opa_helper.build_opa_input(conf, ctx, subsystem)
  local data = build_opa_input(conf, ctx, subsystem)
  data.input.request.body = ctx.umzh_request_body
  return data
end

local function to_set(arr)
  local s = {}
  for _, v in ipairs(arr or {}) do s[v] = true end
  return s
end

-- 400 + FHIR OperationOutcome. issue_code is a FHIR issue-type code
-- ("not-supported", "required", "invalid").
local function reject(issue_code, msg)
  return 400, {
    resourceType = "OperationOutcome",
    issue = { {
      severity    = "error",
      code        = issue_code,
      diagnostics = msg,
    } },
  }
end

function _M.access(conf, ctx)
  -- Use ngx.req directly (not core.request wrapper) so the "truncated" signal
  -- is visible. 20 covers the widest legitimate route (7 params max) with room
  -- to spare; anything beyond that fails closed rather than being silently
  -- forwarded to HAPI in the raw query string.
  local MAX_ARGS = 20
  local args, err = ngx.req.get_uri_args(MAX_ARGS)
  if err == "truncated" then
    return reject("invalid", "too many query parameters")
  end
  args = args or {}
  local allow_params   = to_set(conf.allow_params)
  local allow_includes = to_set(conf.allow_includes)
  local allow_include_iterates = to_set(conf.allow_include_iterates)

  for key, val in pairs(args) do
    if key == "_include" or key == "_include:iterate" then
      -- `_include` / `_include:iterate` are permitted, but only for enumerated
      -- values, each from its own list. An empty list therefore rejects every
      -- value.
      local allowed = (key == "_include") and allow_includes or allow_include_iterates
      local vals = (type(val) == "table") and val or { val }
      for _, v in ipairs(vals) do
        if not allowed[v] then
          return reject("not-supported", "unsupported " .. key .. " value: " .. tostring(v))
        end
      end

    else
      -- Chained search parameter, e.g. subject.name — always rejected.
      if key:find(".", 1, true) then
        return reject("not-supported", "chained search parameter not supported: " .. key)
      end
      -- Modifier (_id:above, code:text) or reverse-chain (_has:...); also
      -- catches _revinclude:iterate and _include:recurse — always rejected.
      -- (_include's colon is in the value, and _include:iterate is handled
      -- above.)
      if key:find(":", 1, true) then
        return reject("not-supported", "search parameter modifier not supported: " .. key)
      end
      -- Deny-by-default param allowlist.
      if not allow_params[key] then
        return reject("not-supported", "unsupported search parameter: " .. key)
      end
      -- _id must identify a single resource — always.
      if key == "_id" then
        if type(val) == "table" then
          return reject("invalid", "_id must be single-valued")
        end
        if type(val) == "string" and val:find(",", 1, true) then
          return reject("invalid", "_id must be single-valued")
        end
      end
    end
  end

  -- Required parameters present?
  for _, req in ipairs(conf["require"] or {}) do
    if args[req] == nil then
      return reject("required", "missing required search parameter: " .. req)
    end
  end

  if conf.forward_body then
    -- OPA sees the first 100 headers only, and HAPI would act on a later one.
    local _, headers_err = ngx.req.get_headers(100)
    if headers_err == "truncated" then
      return reject("invalid", "too many request headers")
    end
    ctx.umzh_request_body = core.request.get_body(MAX_BODY_BYTES, ctx)
  end
end

return _M
