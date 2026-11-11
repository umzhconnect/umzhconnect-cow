# requests — Bruno collection

A [Bruno](https://www.usebruno.com) collection for exploring this node by hand.
Open this folder in Bruno (or run with the `bru` CLI), pick the **Local**
environment, and go.

## Layout

- **Health** — gateway `/healthz` + `/jwks.json` (no auth).
- **Auth** — the L2 token flow in one call:
  - *Get token* → the key custodian signs the `private_key_jwt` assertion **and**
    exchanges it at the auth server, returning the access token (saved to `accessToken`).
- **Gateway** — authenticated FHIR: list / create / update Task, search ServiceRequest.
  These read `{{accessToken}}`, so run the **Auth** folder first.
- **OPA-external** — **the external decision contract** (how any external consumer
  — a gateway or integration platform such as MuleSoft — asks OPA for a decision).
  See the dedicated section below.
- **OPA** — **local dev only**: query the policy engine's *core* rules directly,
  one request per rule (1a–5) plus a deny check, to see what each rule requires.
  This is NOT the external contract (see the ⚠️ below).

## OPA-external — how an external consumer calls OPA (the decision contract)

An external consumer (a gateway or integration platform, e.g. MuleSoft) reaching
OPA through its ingress asks for an authorization decision by forwarding **the
request it is proxying + the client's bearer** — nothing else. OPA decodes the
token and injects the backend address itself.

- **Endpoint:** `POST {{opaUrl}}/v1/data/umzh/authz/gateway/decision` — the **adapter**
  entrypoint (`gateway.rego`). In production point `opaUrl` at OPA's ingress
  (`https://opa.dev.umzhc.io.usz.ch`).
- **Body:** just the FHIR request being proxied, as `input.request`:
  ```json
  { "input": { "request": {
      "method": "GET",
      "path": "/fhir/Task",
      "query_string": "",
      "headers": { "authorization": "Bearer {{bearerToken}}" }
  } } }
  ```
  Always forward the request's raw `query_string`, undecoded and byte for byte as it
  goes to the FHIR server, `""` if it has none: for example
  `"_id=sr-e2e&_include=ServiceRequest:subject&_include=ServiceRequest:requester"`.
  OPA parses it itself and reads `_id` and the `_include` values from it. On a GET
  search (`GET /fhir/<type>`), OPA denies without it, or if it's malformed or names
  `_id` twice. A Task write also sends `body`, either the raw request body as a
  string or the same JSON as an object, and any `if-match` header: OPA denies a
  write it can't read. Forward the same `If-Match` and the same body to the FHIR
  server, after refusing anything but valid `application/fhir+json` without
  duplicate keys: the decision only holds for what OPA was sent.
- **The consumer refuses what the IG doesn't offer.** OPA doesn't check these, so they
  must stop at the consumer: an `If-None-Exist` header (never pass it to the FHIR
  server), a write anywhere but `POST /fhir/Task` or `PUT /fhir/Task/{id}`, and a
  resource id outside `^[A-Za-z0-9.-]{1,64}$`, in the path or in `_id`. On
  MuleSoft, declaring them in the OAS isn't enough unless strict header validation is
  enabled, so check that undeclared headers are rejected.
- **Response:** `{ "result": { "allow": true } }` (allow) or
  `{ "result": { "allow": false, "status_code": 403 } }` (deny). Treat anything
  where `allow` is not `true` as **deny**, and answer the client with `status_code`:
  412 on a Task update with a missing or stale `If-Match`, otherwise 403.
- **The consumer passes NO `fhir_base`, NO scope, NO org, NO context.** OPA decodes
  `scope` / `organization_reference` / `authorization_details` from the bearer, and
  reads `fhir_base` (which FHIR server to read Consent/Task from) from its **own
  trusted config**; a `fhir_base` in the input is ignored. This is deliberate and
  security-critical: if a caller could set `fhir_base`, it could point OPA at a rogue
  FHIR server serving fake Consents and get `allow: true` — an authorization bypass.
  So the contract is strictly *request + token in; decision out*.
- **Token (`bearerToken`):** the client's access token that the consumer is
  forwarding. For testing, mint one via the **Auth** folder and copy `accessToken`
  into `bearerToken`, or paste any token from your auth server. Its
  scope/org/context decide the outcome (OPA does **not** verify the signature,
  but it must carry the right claims). The `Decide - …` requests mirror the
  gateway's real routes (Task search/read/create/update, ServiceRequest search, read
  by id); the graph/consent ones (Task read/update, SR search, read by id) are
  **data-dependent** (OPA fetches Consent/Task/SR), so bring the stack up and seed
  (`tests/scripts/seed.sh up`) for them to return `true`.

> ⚠️ **Ingress scope.** The OPA ingress must expose **only** the adapter path
> (`/v1/data/umzh/authz/gateway`), never the core `/v1/data/umzh/authz/allow` —
> the core policy trusts the token claims in its input (see the OPA folder note).

## OPA (core policy) — dev exploration only

The **OPA** folder queries the *core* policy, `POST {{opaUrl}}/v1/data/umzh/authz/allow`,
with a hand-crafted flat `input` holding the token's already-mapped
`organization_reference`, `scope` and `context` — no JWT needed. OPA
fetches from its own configured `fhir_base`. That's handy for understanding each
rule in isolation, but it is **not** how an external caller should talk to OPA:
never expose `/allow` externally, because it lets the caller claim any
organization, scope or context.

## Environment (`environments/Local.bru`)

Points at the default host ports (gateway `:9081`, custodian `:9087`, OPA `:9181`,
auth server `:8180`), the `orgA` test org identity, and `orgRef` set to
the sandbox fulfiller org. Adjust these to your ecosystem — `orgRef` must equal
the token's `organization_reference`. The client id is not set here: the
custodian always uses its own `CLIENT_ID` (`L2_CLIENT_ID` in `.env`).

`accessToken`, `taskId`, `taskVersion`, and `bearerToken` are secret vars — filled at
runtime (or pasted) — leave them blank in the file.

## Typical flow

Auth › *Get token* → Gateway › *Create Task* → *List Tasks* → *Update Task*.

For an automated, assert-checked version of these calls, see `../tests`.
