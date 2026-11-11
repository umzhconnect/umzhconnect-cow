# opa — consent / context policy

| Here (party-local) | What |
|---|---|
| `policies/` | The rego **policies** — party-local hard copies (`gateway.rego`, `main.rego`). Bind-mounted into the `opa` container at `/policies` (compose) / generated into the `opa-policies` ConfigMap (k8s). |
| `opa-config.json` | The party's OPA **data document** — just `fhir_base` (the base HAPI's `clinical-orders` partition). Static; mounted at `/config/opa-config.json`. **Compose only** — k8s uses its own `opa-config` ConfigMap (different HAPI address). |
| `opa.yaml`, `ns.yaml`, `kustomization.yaml` | k8s Deployment + Service + `opa-config` ConfigMap, the `opa` **namespace**, and the kustomize entrypoint. |
| `ingress.yaml` | Ingress exposing **only the gateway adapter decision entrypoint** (`/v1/data/umzh/authz/gateway`) so an external consumer (e.g. MuleSoft) can query decisions. |

`policies/` holds only what the `umzh/authz/gateway` entrypoint needs:
`gateway.rego` (the generic gateway/PEP request adapter — serves the APISIX
gateway AND external consumers like MuleSoft) and `main.rego` (the consent /
context rules it delegates to). These were forked from the two-party UMZH
Connect sandbox (`services/opa/policies` there) and are now owned here —
reconcile the two manually. The sandbox's `capabilities.rego` /
`apisix_guarded.rego` (the OPA data-as-code param allowlist) are **not** copied,
because the gateway enforces param/`_include` allowlists at the edge via
`umzh-capability-guard` instead.

**Authorization is SMART-scope + context-centric.** Every rule in `main.rego`
carries its own scope (`system/<Type>.<action>`) and identity condition
(`organization_reference` match / consent / context graph). There is no
coarse realm-role gate — `gateway.rego` delegates straight to `main.rego`. The one
rule without a scope is `GET /fhir/metadata` (the CapabilityStatement), which
still needs a bearer token, like every request through the adapter.

## How a request flows

```
API gateway (PEP) ── POST input.request {method, path, query_string, headers, body} ──▶ umzh/authz/gateway (gateway.rego)
  gateway.rego: decode the (already-authenticated) bearer and parse the raw query
               string into a flat input, then evaluate data.umzh.authz.allow
               ──▶ main.rego: work out what the path and _id target, apply the rules
                   (fetching from its own fhir_base) ──▶ allow = true/false
```

> **Trust boundary:** `gateway.rego` decodes but does **not** verify the JWT
> signature — the API gateway authenticates the token first. OPA-side signature
> verification is a tracked improvement — see `../BACKLOG.md`.

### What each layer checks

The API gateway in front of OPA (such as APISIX, MuleSoft or Kong) validates the
request's shape, and OPA relies on that. It must do these, because OPA doesn't:

| The API gateway must | Why | This repo's APISIX |
|---|---|---|
| Authenticate the bearer token (signature, issuer, expiry) | OPA only decodes the claims | `openid-connect` |
| Refuse an `If-None-Exist` header | The IG's `conditionalCreate` is false, and HAPI would answer with the match, whoever owns it | `umzh-capability-guard` → `400` |
| Allow only the IG's operations, query parameters, `_include` / `_include:iterate` values and headers, per route | Everything else is refused at the edge; for example, any write but `POST /fhir/Task` or `PUT /fhir/Task/{id}` (HAPI ignores `If-Match` on a conditional `PUT /Task?_id={id}`) | Routes → `404`; `umzh-capability-guard` → `400` |
| Refuse a resource id outside `^[A-Za-z0-9.-]{1,64}$`, in the path or in `_id`, and a repeated `_id` | OPA builds its fetch URL from the id. Anything else can mean one resource to OPA's fetch and another to HAPI's search: `good#/QuestionnaireResponse/victim` is `good` to OPA | `_id`: `umzh-capability-guard` → `400`. Path: routes → `404` |
| On `GET /fhir/Task`, set `requester=<the token's organization_reference>` on the query it forwards to the FHIR server, replacing any the client sent | Rule 1a only decides whether the search may run; this filter limits it to the caller's own Tasks. Without it, the search returns every Task | `umzh-task-requester-inject` |
| Refuse a write body that isn't valid `application/fhir+json`, or that has duplicate keys | OPA and the FHIR server parse the body separately; with a duplicate key, each could keep a different value, such as a different `requester` | `umzh-capability-guard` on the write routes: wrong `Content-Type` → `415`; not one JSON object, over 1 MB, or a key twice in one object at any depth (compared decoded, so `"requester"` counts) → `400` |
| Forward to OPA exactly what it forwards to the FHIR server: the raw query string (`""` if none), `If-Match` and the body, as the raw string or as the same JSON object | OPA reads `_id` and the `_include` values from the query string, and its decision only holds for what it was sent. The requester filter is the one addition, made after OPA's decision | `umzh-capability-guard` sets `input.request.query_string`, and `body` as the raw string |

OPA checks none of these. It denies what it can't interpret instead of guessing:
- **No bearer token**, or one that doesn't decode, on every request, `/fhir/metadata` included.
- **A path deeper than `/fhir/<type>/<id>`**, such as a `/_history/<n>`: OPA can't name what it targets.
- **A GET search (`GET /fhir/<type>`) whose query string it can't use:** missing, not a string, malformed (bad percent-encoding, `;` as a separator), or naming `_id` more than once. It parses the query string itself, with `urlquery.decode_object`, so a repeated parameter keeps every value. A read names its resource in the path, and a write's query decides nothing, so they don't need one.

`main.rego` rules 1b/1d/4/4b call `http.send` back to the FHIR server
(`fhir_base`) to read the live Task / Consent / ServiceRequest that the decision
depends on. `main.rego` reads `fhir_base` and the optional backend credential from
OPA's own configuration (see below), never from the input, so whoever calls it can't
choose the server or the credential. With no `fhir_base` configured, it allows
nothing.

## Rules (`main.rego`)

`default allow := false` — every request is denied unless a rule below matches.

Every rule also needs this: `_include` and `_include:iterate` only on a search by
`_id`. Without one, the search could match any number of resources, and the include
would pull in what each of them references. A read by id may not include either.

| Rule | Matches | Requires |
|---|---|---|
| **1a** | `GET /fhir/Task` (search) | `system/Task.s` **and** non-empty `organization_reference` (the gateway's injected `?requester=` filter scopes *what* is returned; this fails closed if the org ref is absent). No `_include`: it needs `_id` |
| **1b** | `GET /fhir/Task/{id}`, `GET /fhir/Task?_id={id}` | `system/Task.r`, or `.s` for the search, **and** the fetched `Task.requester` == caller's `organization_reference`. A context-gated `_include` also needs the context `Task/{id}` |
| **1c** | `POST /fhir/Task` (create) | `system/Task.c` **and** the body's `Task.requester` == caller **and** no `Task.output` or `businessStatus` |
| **1d** | `PUT /fhir/Task/{id}` | `system/Task.u` **and** the fetched `Task.requester` == caller **and** `If-Match` names its current version (else `412`) **and** the body differs only by a cancel while `requested`/`accepted`, or an answer while `awaiting-information` (`input` added, `businessStatus` removed). `meta`, `text` and `lastModified` are not compared |
| **3** | `GET /fhir/Questionnaire/{id}`, `GET /fhir/Questionnaire` | `system/Questionnaire.r`, or `.s` for the search |
| **4** | `GET` of any type except Task | `system/<Type>.r`, or `.s` for a search, **and** an active, non-expired **Consent** (actor == caller) for a **ServiceRequest** context **and** that SR is `active` **and** the resource is in its graph. A QuestionnaireResponse is also in the graph if its `basedOn` is the SR's relative reference |
| **4b** | `GET` of any type except Task | `system/<Type>.r`, or `.s` for a search, **and** a **Task** context whose fetched `Task.requester` == caller **and** the resource is in that Task's `output` graph |
| **5** | `GET /fhir/metadata` | no scope: any authenticated caller may read the CapabilityStatement. Other methods on this path are denied |

Rule numbers are kept stable so tests, requests and docs keep their names: rules 2
and 6 were removed in #7.

**What the context graphs contain.** Rule 4's ServiceRequest graph is the
ServiceRequest itself plus what its `subject`, `requester`, `reasonReference`,
`supportingInfo` and `insurance` reference. `performer` is left out: it's the
receiving organization. A QuestionnaireResponse whose `basedOn` is the
ServiceRequest also belongs, the one back-reference the IG admits. Rule 4b's Task
graph is the Task plus what its `output[].valueReference` references. `Task.input`
is left out: the Placer fills it, so it mustn't decide what the Placer can read.

Consent and ServiceRequest are re-read live on every request (not cached), so
revocation, expiry and a ServiceRequest leaving `active` take effect immediately.
A token carries its context in the `authorization_details` claim: none or several
denies every context-gated request. `gateway.rego` hands `main.rego` a flat input:
the token's `organization_reference`, `scope` and one `context` (`""` for none or
several) next to the request's fields, the query parameters as `query_params` (one
`{name: value}` entry per value, defaulting to `[]`; `null` when the query string
didn't parse, which denies a GET search) and the `If-Match` header as
`header_if_match`. The input names no resource type, id or read/search flag:
`main.rego` works them out from `path` and `_id`. `/fhir/<type>` is a search (`s`
scope), its id if any from `_id`; `/fhir/<type>/<id>` is a read (`r` scope). Method
and id alone can't tell them apart: `GET /fhir/Task/t1` and `GET /fhir/Task?_id=t1`
both name `Task/t1`. The comment at the top of `main.rego` shows the full input.

## Optional backend auth (OPA → FHIR server)

OPA queries the FHIR server **directly** (`fhir_base`, the base HAPI), not through
the clinical-orders proxy — so the proxy's `PROXY_BACKEND_AUTHORIZATION` does not
cover OPA's calls. If that FHIR server requires credentials, set
`FHIR_BACKEND_AUTHORIZATION` to the full `Authorization` header value
(`Basic <base64(user:pass)>`); OPA then attaches it to its `http.send` fetches.
Empty (the default) sends no such header — unchanged behaviour.

**It does NOT go in `opa-config.json`.** That file is committed and holds only the
non-secret `fhir_base`; a credential there would be a secret in git. Instead
`main.rego` reads it from the OPA **process environment** via
`opa.runtime().env.FHIR_BACKEND_AUTHORIZATION`, inside the function that builds
its FHIR requests, and adds it to the headers only when non-empty. It's read in a
function, not a rule, because OPA's data API returns the value of every rule (`GET
/v1/data/umzh/authz/...`) but never of a function. Inject it at runtime — compose
`environment:` (from `.env`) or, in k8s, a Secret on the OPA Deployment. (This is why the value can't live in the data
document: the `openpolicyagent/opa` image is distroless — no shell/`envsubst` — so
env-based config must be read through `opa.runtime().env`, not rendered into a
file.)

## Overriding `fhir_base` (point OPA at a different backend)

By default `fhir_base` comes from the committed `opa-config.json` data document (the
bundled base HAPI's `clinical-orders` partition). A party running this **same**
policy + config bundle against a **different** FHIR backend — e.g. a cluster-
external, commercial FHIR server — can override it **without editing** the committed
config by setting the `FHIR_BASE` **process environment** variable:

- compose: `OPA_FHIR_BASE` in `.env` (mapped to the container's `FHIR_BASE`);
- k8s: uncomment the `FHIR_BASE` env on the OPA Deployment in `opa.yaml`.

`main.rego` resolves it as **env wins when set & non-empty, else the data
document** (`opa.runtime().env.FHIR_BASE` → `data.config.fhir_base`). This mirrors
the `FHIR_BACKEND_AUTHORIZATION` mechanism above (same distroless-image reason: env
config must be read through `opa.runtime().env`, not rendered into a file) and pairs
naturally with the clinical-orders proxy's `PROXY_*` external-backend knobs. Leave it
unset for the bundled HAPI. It is **never** taken from the caller — only the process
environment or the committed data document.

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

### External access (e.g. MuleSoft) — `ingress.yaml`

An external consumer queries OPA for decisions through the ingress at
`https://opa.dev.umzhc.io.usz.ch`, using the **gateway adapter** entrypoint —
exactly like the APISIX gateway does internally, just over the ingress. It
forwards the request it is proxying + the client's bearer; it passes **no**
`fhir_base` and no scope/org (OPA decodes those from the token, and reads
`fhir_base` from its own config). See `requests/OPA-external/` and
`requests/README.md` for the full contract.

```
POST https://opa.dev.umzhc.io.usz.ch/v1/data/umzh/authz/gateway/decision
  { "input": { "request": { "method": "...", "path": "/fhir/...", "query_string": "...",
                            "headers": { "authorization": "Bearer <token>" } } } }
  # → { "result": { "allow": true } }
  # or { "result": { "allow": false, "status_code": 403 | 412 } }
```

⚠️ **The ingress deliberately publishes only `/v1/data/umzh/authz/gateway`** — not
the core `/v1/data/umzh/authz/allow` (which trusts the token claims in its input, so a caller
could claim any organization, scope or context → bypass), and not OPA's data/policy management (`/v1/policies`, `/v1/data`
PUT/PATCH, `/v1/compile`, `/v1/query`). This path scoping is **edge** control, not
authentication: OPA still trusts whoever reaches it (and does not verify the JWT
signature — see the trust boundary above / `../BACKLOG.md`). In front of it you
must also authenticate the platform (mTLS / a gateway credential at the WAF,
ideally POST-only), and/or enable OPA's own API authn/authz (`--authentication`,
`--authorization`) if anything but the trusted platform could reach the Service.
Keep the base HAPI and the rest of OPA's API off the public internet
(NetworkPolicy).

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
| `main_test.rego` | `umzh.authz_test` | every rule and its branches (scope present/absent, org match/mismatch, consent active/expired/missing, resource in/out of graph); how the resource type, id and read/search come from `path` and `_id`, and the denial of deeper paths and unusable query parameters; plus the backend configuration (`fhir_base`, and the backend-auth header attached when set, absent when unset, and held by no rule) |
| `adapter_test.rego` | `umzh.authz.gateway_test` | `gateway.rego`'s mapping of the request into `main.rego`'s flat input: the raw `query_string` into `query_params` (`null` when it doesn't parse), the token's claims and one context, `If-Match`; the explicit denial without a bearer token; and decisions through the real `main.rego` |

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

The backend-auth tests go one level deeper: they set the OPA environment with
`with opa.runtime as {...}`, and their mocks assert on `req.headers.Authorization`,
proving the credential reaches the actual `http.send` request, isn't taken from the
input, and is held by no rule. `tests/opa/data.json` stands in for
`opa-config.json`, so every test has a `fhir_base`.
