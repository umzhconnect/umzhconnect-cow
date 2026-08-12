# opa — consent / fhirContext policy

| Here (party-local) | What |
|---|---|
| `policies/` | The rego **policies** — party-local hard copies (`apisix.rego`, `main.rego`). Bind-mounted into the `opa` container at `/policies` (compose) / generated into the `opa-policies` ConfigMap (k8s). |
| `opa-config.json` | The party's OPA **data document** — just `fhir_base` (the base HAPI's `clinical-orders` partition). Static; mounted at `/config/opa-config.json`. **Compose only** — k8s uses its own `opa-config` ConfigMap (different HAPI address). |
| `opa.yaml`, `ns.yaml`, `kustomization.yaml` | k8s Deployment + Service + `opa-config` ConfigMap, the `opa` **namespace**, and the kustomize entrypoint. |
| `ingress.yaml` | Ingress exposing OPA's **decision surface only** (`/v1/data/umzh/authz`) so an external platform (MuleSoft) can query decisions. |

`policies/` holds only what the external gateway's `umzh/authz/apisix` entrypoint
needs: `apisix.rego` (the APISIX request adapter) and `main.rego` (the consent /
fhirContext rules it delegates to). These were forked from the two-party UMZH
Connect sandbox (`services/opa/policies` there) and are now owned here —
reconcile the two manually. The sandbox's `capabilities.rego` /
`apisix_guarded.rego` (the OPA data-as-code param allowlist) are **not** copied,
because the gateway enforces param/`_include` allowlists at the edge via
`umzh-capability-guard` instead.

**Authorization is SMART-scope + context-centric.** Every rule in `main.rego`
carries its own scope (`system/<Type>.<action>`) and identity condition
(`organization_reference` match / consent / fhirContext graph). There is no
coarse realm-role gate — `apisix.rego` delegates straight to `main.rego`. The one
rule without a scope is `/fhir/metadata` (the public CapabilityStatement).

## How a request flows

```
APISIX opa plugin ── POST input.request {method, path, query, headers} ──▶ umzh/authz/apisix (apisix.rego)
  apisix.rego: decode the (already-validated) bearer, parse the path, read
               fhir_base from data.config, then evaluate data.umzh.authz.allow
               with the mapped input ──▶ main.rego rules ──▶ allow = true/false
```

`main.rego` rules 1b/1d/4/4b call `http.send` back to the FHIR server
(`input.fhir_base`) to read the live Task / Consent / ServiceRequest that the
decision depends on.

## Rules (`main.rego`)

`default allow := false` — every request is denied unless a rule below matches.

| Rule | Matches | Requires |
|---|---|---|
| **1a** | `GET /fhir/Task` (search) | `system/Task.s` **and** non-empty `organization_reference` (the gateway's injected `?requester=` filter scopes *what* is returned; this fails closed if the org ref is absent) |
| **1b** | `GET /fhir/Task/{id}` | `system/Task.r` **and** the fetched `Task.requester` == caller's `organization_reference` |
| **1c** | `POST /fhir/Task` (create) | `system/Task.c` — scope only (the Task is owned by the partner, so ownership can't be required) |
| **1d** | `PATCH /fhir/Task/{id}` | `system/Task.u` **and** the fetched `Task.owner` == caller (owner-only writes keep the Task graph trustworthy) |
| **2** | any `QuestionnaireResponse` op | `system/QuestionnaireResponse.<action>` — no consent needed |
| **3** | `GET /fhir/Questionnaire/{id}` | `system/Questionnaire.r` |
| **4** | `GET` of any type except Task/QuestionnaireResponse | `system/<Type>.r` **and** an active, non-expired **Consent** (actor == caller) for a **ServiceRequest** fhirContext entry **and** the resource is in that SR's graph |
| **4b** | `GET` of any type except Task | `system/<Type>.r` **and** an active Consent for a **Task** fhirContext entry **and** the resource is in that Task's `output` graph |
| **5** | `GET /fhir/metadata` | nothing — public CapabilityStatement |
| **6** | `GET` on `Organization` / `Practitioner` / `PractitionerRole` | `system/<Type>.r` — directory reads |

Consent is re-read live on every request (not cached) so revocation and expiry
take effect immediately; the ServiceRequest fetch is cached (immutable for the
workflow). Each fhirContext entry is paired with its **own** Consent — a Consent
covering one context never grants access to another.

## Optional backend auth (OPA → FHIR server)

OPA queries the FHIR server **directly** (`fhir_base`, the base HAPI), not through
the clinical-orders proxy — so the proxy's `PROXY_BACKEND_AUTHORIZATION` does not
cover OPA's calls. If that FHIR server requires credentials, set
`FHIR_BACKEND_AUTHORIZATION` to the full `Authorization` header value
(`Basic <base64(user:pass)>`); OPA then attaches it to its `http.send` fetches.
Empty (the default) sends no such header — unchanged behaviour.

**It does NOT go in `opa-config.json`.** That file is committed and holds only the
non-secret `fhir_base`; a credential there would be a secret in git. Instead
`apisix.rego` reads it from the OPA **process environment** via
`opa.runtime().env.FHIR_BACKEND_AUTHORIZATION` and passes it into the policy input
as `fhir_authorization`; `main.rego` adds it to the request headers only when
non-empty. Inject it at runtime — compose `environment:` (from `.env`) or, in k8s,
a Secret on the OPA Deployment. (This is why the value can't live in the data
document: the `openpolicyagent/opa` image is distroless — no shell/`envsubst` — so
env-based config must be read through `opa.runtime().env`, not rendered into a
file.)

## Kubernetes

OPA runs in its own **`opa`** namespace, self-contained:

```bash
kubectl apply -k opa/          # preview: kubectl kustomize opa/
```

Produces: `Namespace opa`, `Deployment opa` + `Service opa` (reached by the gateway
at `opa.opa.svc.cluster.local:8181` — set that as `OPA_URL` in the
`apisix-gateway-config` ConfigMap), the generated `opa-policies` ConfigMap (the
shared `policies/*.rego`, mounted at `/policies`), and the `opa-config` ConfigMap.

**OPA talks to HAPI directly, not the clinical-orders proxy.** `fhir_base` in the
k8s `opa-config` points cross-namespace at the base HAPI's partition
(`hapi-fhir.hapi-fhir.svc.cluster.local:8080/fhir/clinical-orders`). OPA is
an internal consumer of the source of truth: it uses the explicit partition path
and skips the outward proxy's partition-hiding / self-link rewriting (irrelevant to
policy) and its extra hop on the hot path. This is why `fhir_base` is a
k8s-specific ConfigMap (the HAPI address differs from compose) while the *policies*
stay shared.

To enable optional backend auth, create the `opa-backend-fhir-auth` Secret (key
`authorization`); the Deployment reads it as `FHIR_BACKEND_AUTHORIZATION` with
`optional: true`, so it's a no-op when the Secret is absent.

### External access (MuleSoft) — `ingress.yaml`

An external integration platform (MuleSoft) queries OPA for decisions through the
ingress at `https://opa.dev.umzhc.io.usz.ch`, e.g.:

```
POST https://opa.dev.umzhc.io.usz.ch/v1/data/umzh/authz/allow
  { "input": { …the rule input… } }        # → { "result": true|false }
```

⚠️ **The ingress deliberately publishes only `/v1/data/umzh/authz`.** OPA's REST
API otherwise allows *writing* data and policies (`/v1/policies`, `/v1/data`
PUT/PATCH, `/v1/compile`, `/v1/query`) — never expose it wholesale. This path
scoping is **edge** control, not authentication: OPA still trusts whoever reaches
it. In front of it you must also authenticate the platform (mTLS / a gateway
credential at the WAF, ideally POST-only), and/or enable OPA's own API
authn/authz (`--authentication`, `--authorization`) if anything but the trusted
platform could reach the Service. Keep the base HAPI and the rest of OPA's API off
the public internet (NetworkPolicy).

> **Note:** OPA-level API authentication/authorization (token authn + an authz
> policy that permits only POST to the decision path) is **not enabled yet** — it
> can be enforced at a later stage. For now access is controlled at the edge
> (ingress path scoping + the platform/WAF in front).

## Tests

Hermetic unit tests — no stack, no auth, no HAPI: the `http.send` calls are mocked
with `with http.send as <fn>`, so the whole suite runs offline.

```bash
tests/scripts/opa-test.sh              # uses local `opa`, else the opa image
tests/scripts/opa-test.sh --coverage   # + coverage report
```

The runner (`tests/scripts/opa-test.sh`) invokes `opa test opa/policies tests/opa`.
Two test files under `tests/opa/`:

| File | Package | Covers |
|---|---|---|
| `main_test.rego` | `umzh.authz_test` | every rule 1a–6 and its branches (scope present/absent, org match/mismatch, consent active/expired/missing, resource in/out of graph), plus the optional backend-auth header (attached when set, absent when unset) |
| `adapter_test.rego` | `umzh.authz.apisix_test` | `apisix.rego`'s path/query parsing (`resource_type`, `resource_id`, `canonical_path`) for read-by-id vs. search shapes |

**How the mocking works.** `main_test.rego` defines an input builder `req_in(method,
type, id, scope, org, ctx)` that produces the exact input shape `main.rego`
expects, and a set of `http.send` mocks that branch on the request URL
(`contains(req.url, "/Task/")`, `"/Consent?data="`, `"/ServiceRequest/"`) to return
canned Task / Consent / ServiceRequest bodies. A test wires them together, e.g.:

```rego
test_1b_read_allowed_requester_match if {
    data.umzh.authz.allow with input as req_in("GET", "Task", "t1", "system/Task.r", org_a, [])
        with http.send as mock_task_a
}
```

The backend-auth tests go one level deeper: their mocks additionally assert on
`req.headers.Authorization`, proving the credential wired through from
`input.fhir_authorization` into the actual `http.send` request.
