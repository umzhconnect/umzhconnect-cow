# opa — consent / fhirContext policy

| Here (party-local) | What |
|---|---|
| `policies/` | The rego **policies** — party-local hard copies (`apisix.rego`, `main.rego`). Bind-mounted into the `opa` container at `/policies`. |
| `opa-config.json` | The party's OPA **data document** — just `fhir_base` (the base HAPI's `clinical-orders` partition). Static; mounted at `/config/opa-config.json`. |

`policies/` holds only what the external gateway's `umzh/authz/apisix` entrypoint
needs: `apisix.rego` (the APISIX request adapter) and `main.rego` (the consent /
fhirContext rules it delegates to). These were forked from the two-party UMZH
Connect sandbox (`services/opa/policies` there) and are now owned here —
reconcile the two manually. The sandbox's `capabilities.rego` /
`apisix_guarded.rego` (the OPA data-as-code
param allowlist) are **not** copied, because the gateway enforces param/`_include`
allowlists at the edge via `umzh-capability-guard` instead.

**Authorization is SMART-scope + context-centric.** Every rule in `main.rego`
carries its own scope (`system/<Type>.<action>`) and identity condition
(`organization_reference` match / consent / fhirContext graph). There is no
coarse realm-role gate — `apisix.rego` delegates straight to `main.rego` — so the
config document has nothing to render (hence static, no `opa-config-init`
one-shot). The one rule without a scope is `/fhir/metadata` (the public
CapabilityStatement).

Why a one-shot instead of self-rendering (as the nginx proxies do): the
`openpolicyagent/opa` image is distroless — no shell, no `envsubst` — so it
cannot substitute env vars itself. This is the only remaining central render
step; everything else self-renders.
