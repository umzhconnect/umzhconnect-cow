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
- **OPA** — query the policy engine **directly** (no gateway, no token): one
  request per authorization rule (1a–6) plus a default-deny check. Each POSTs a
  hand-crafted `input` to `{{opaUrl}}/v1/data/umzh/authz/allow` and returns
  `{ "result": true|false }`, so you can see exactly what each rule requires. The
  scope/identity-only rules (1a, 1c, 2, 3, 5, 6) are deterministic; the
  graph/consent rules (1b, 1d, 4, 4b) are **data-dependent** — OPA does `http.send`
  to the FHIR server, so they only return `true` when the referenced
  Task/Consent/ServiceRequest exist (seed them via `tests/scripts/seed.sh`, or run
  `run-tests.sh` which seeds/tears down). Each request's `docs` says which case it
  is. Note `opaFhirBase` is the **OPA-internal** address (`hapi-fhir:8080/...`),
  used by OPA's own fetch, not by Bruno.

## Environment (`environments/Local.bru`)

Points at the default host ports (gateway `:9081`, custodian `:9087`, OPA `:9181`,
auth server `:8180`), the `orgA`/`orgB` test org identities, `opaFhirBase` (OPA's
in-cluster FHIR address), `clientId: fulfiller-client-l2`, and `orgRef` set to the
sandbox fulfiller org. Adjust these to your ecosystem — `clientId` must be a client
the auth server knows whose `jwks.url` resolves to this node's `/jwks.json`, and
`orgRef` must equal the token's `organization_reference`.

`assertion`, `accessToken`, and `taskId` are filled in at runtime by the request
scripts — leave them blank.

## Typical flow

Auth › *1 Sign assertion* → Auth › *2 Exchange for token* → Gateway › *Create
Task* → *List Tasks* → *Patch Task*.

For an automated, assert-checked version of these calls, see `../tests`.
