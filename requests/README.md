# requests — Bruno collection

A [Bruno](https://www.usebruno.com) collection for exploring this node by hand.
Open this folder in Bruno (or run with the `bru` CLI), pick the **Local**
environment, and go.

## Layout

- **Health** — gateway `/healthz` + `/jwks.json`, registry `/metadata` (no auth).
- **Registry** — list Organizations; a write that the read-only proxy rejects (403).
- **Auth** — the two-step L2 token flow:
  1. *Sign assertion* → the key custodian mints a `private_key_jwt` (saved to `assertion`).
  2. *Exchange for token* → swap it at the auth server for an access token (saved to `accessToken`).
- **Gateway** — authenticated FHIR: list / create / patch Task, search ServiceRequest.
  These read `{{accessToken}}`, so run the **Auth** folder first.

## Environment (`environments/Local.bru`)

Points at the default host ports (gateway `:9081`, registry `:9084`, custodian
`:9087`, auth server `:8180`), `clientId: fulfiller-client-l2`, and `orgRef` set
to the sandbox fulfiller org. Adjust these to your ecosystem — `clientId` must be
a client the auth server knows whose `jwks.url` resolves to this node's
`/jwks.json`, and `orgRef` must equal the token's `organization_reference`.

`assertion`, `accessToken`, and `taskId` are filled in at runtime by the request
scripts — leave them blank.

## Typical flow

Auth › *1 Sign assertion* → Auth › *2 Exchange for token* → Gateway › *Create
Task* → *List Tasks* → *Patch Task*.

For an automated, assert-checked version of these calls, see `../tests`.
