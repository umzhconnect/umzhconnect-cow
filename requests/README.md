# requests — Bruno collection

A [Bruno](https://www.usebruno.com) collection for exploring this node by hand.
Open this folder in Bruno (or run with the `bru` CLI), pick the **Local**
environment, and go.

## Layout

- **Health** — gateway `/healthz` + `/jwks.json` (no auth).
- **Auth** — the two-step L2 token flow:
  1. *Sign assertion* → the key custodian mints a `private_key_jwt` (saved to `assertion`).
  2. *Exchange for token* → swap it at the auth server for an access token (saved to `accessToken`).
- **Gateway** — authenticated FHIR: list / create / patch Task, search ServiceRequest.
  These read `{{accessToken}}`, so run the **Auth** folder first.
- **OPA-external** — **the external decision contract** (how any external consumer
  — a gateway or integration platform such as MuleSoft — asks OPA for a decision).
  See the dedicated section below.
- **OPA** — **local dev only**: query the policy engine's *core* rules directly,
  one request per rule (1a–6) plus a deny check, to see what each rule requires.
  This is NOT the external contract (see the ⚠️ below).

## OPA-external — how an external consumer calls OPA (the decision contract)

An external consumer (a gateway or integration platform, e.g. MuleSoft) reaching
OPA through its ingress asks for an authorization decision by forwarding **the
request it is proxying + the client's bearer** — nothing else. OPA decodes the
token and injects the backend address itself.

- **Endpoint:** `POST {{opaUrl}}/v1/data/umzh/authz/gateway/allow` — the **adapter**
  entrypoint (`gateway.rego`). In production point `opaUrl` at OPA's ingress
  (`https://opa.dev.umzhc.io.usz.ch`).
- **Body:** just the FHIR request being proxied, as `input.request`:
  ```json
  { "input": { "request": {
      "method": "GET",
      "path": "/fhir/Task",
      "query": {},
      "headers": { "authorization": "Bearer {{bearerToken}}" }
  } } }
  ```
- **Response:** `{ "result": true }` (allow) or `{ "result": false }` (deny).
  Treat anything that is not `true` as **deny**.
- **The consumer passes NO `fhir_base`, NO scope, NO org, NO context.** OPA decodes
  `scope` / `organization_reference` / `fhirContext` from the bearer, and injects
  `fhir_base` (which FHIR server to read Consent/Task from) from its **own trusted
  config**. This is deliberate and security-critical: if a caller could set
  `fhir_base`, it could point OPA at a rogue FHIR server serving fake Consents and
  get `allow: true` — an authorization bypass. So the contract is strictly
  *request + token in; boolean out*.
- **Token (`bearerToken`):** the client's access token that the consumer is
  forwarding. For testing, mint one via the **Auth** folder and copy `accessToken`
  into `bearerToken`, or paste any token from your auth server. Its
  scope/org/fhirContext decide the outcome (OPA does **not** verify the signature,
  but it must carry the right claims). The `Decide - …` requests mirror the
  gateway's real routes (Task search/create/update, ServiceRequest search, read by
  id); the graph/consent ones (Task update, SR search, read by id) are
  **data-dependent** (OPA fetches Consent/Task/SR), so bring the stack up and seed
  (`tests/scripts/seed.sh up`) for them to return `true`.

> ⚠️ **Ingress scope.** The OPA ingress must expose **only** the adapter path
> (`/v1/data/umzh/authz/gateway`), never the core `/v1/data/umzh/authz/allow` —
> the core policy trusts a caller-supplied `fhir_base` (see the OPA folder note).

## OPA (core policy) — dev exploration only

The **OPA** folder queries the *core* policy, `POST {{opaUrl}}/v1/data/umzh/authz/allow`,
with a hand-crafted `input` that includes `fhir_base` (via `opaFhirBase`) and the
already-mapped `token` — no JWT needed. That's handy for understanding each rule in
isolation, but it is **not** how an external caller should talk to OPA: never
expose `/allow` externally, because it lets the caller choose `fhir_base`.
`opaFhirBase` is the OPA-internal FHIR address used by OPA's own fetch (not by
Bruno), and it's a dev convenience only.

## Environment (`environments/Local.bru`)

Points at the default host ports (gateway `:9081`, custodian `:9087`, OPA `:9181`,
auth server `:8180`), the `orgA`/`orgB` test org identities, `opaFhirBase` (OPA's
in-cluster FHIR address, used by the OPA-core folder only), `clientId:
fulfiller-client-l2`, and `orgRef` set to the sandbox fulfiller org. Adjust these
to your ecosystem — `clientId` must be a client the auth server knows whose
`jwks.url` resolves to this node's `/jwks.json`, and `orgRef` must equal the
token's `organization_reference`.

`assertion`, `accessToken`, `taskId`, and `bearerToken` are secret vars — filled at
runtime (or pasted) — leave them blank in the file.

## Typical flow

Auth › *1 Sign assertion* → Auth › *2 Exchange for token* → Gateway › *Create
Task* → *List Tasks* → *Patch Task*.

For an automated, assert-checked version of these calls, see `../tests`.
