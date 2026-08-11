# tests

Two layers, following the testing pyramid:

- **OPA policy unit tests** (`tests/opa/`, run with `opa test`) — exhaustive,
  hermetic coverage of every authorization rule. No stack, no auth, no HAPI.
- **Integration tests** ([Hurl](https://hurl.dev), `tests/hurl/`) — thin
  end-to-end checks through the real gateway → OPA → HAPI, with a throwaway mock
  auth issuer (or a real auth server). Proves the wiring.

---

## OPA policy unit tests (rule coverage)

`tests/opa/main_test.rego` covers rules 1a–6 and every branch (scope present/
absent, org match/mismatch, consent active/expired/missing, resource in/out of
graph); `tests/opa/adapter_test.rego` covers the APISIX path/query parsing in
`apisix.rego`. Rules that call `http.send` (Task/Consent/ServiceRequest fetches)
mock it with `with http.send as <fn>`, so the suite is fully self-contained.

```bash
tests/scripts/opa-test.sh              # uses local `opa`, else the opa image
tests/scripts/opa-test.sh --coverage   # coverage report
```

This is where pure-policy cases live (e.g. consent-actor mismatch, expired
consent) — they don't need the gateway, so they're not duplicated in Hurl.

---

## Integration tests (Hurl)

```bash
keys/gen-keys.sh l2
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build
tests/scripts/run-tests.sh
```

The overlay adds `mock-auth` and points the gateway's `AUTH_DISCOVERY_URL` at it.
Without an auth source the runner executes only the unauthenticated files and
skips the role scenarios.

| File | Auth | Checks |
|------|------|--------|
| `01-health.hurl` | none | gateway `/healthz` + `/jwks.json`, registry `/metadata`, custodian, OPA |
| `02-registry-readonly.hurl` | none | GET on `Organization`/`Endpoint`/`HealthcareService` allowed; writes / other types → `403` |
| `03-auth-negative.hurl` | none | gateway rejects missing / malformed / tampered bearer → `401` |
| `placer.hurl` | token | **this node as placer** — no-bearer `401`; authorized `ServiceRequest` search + `_include`, read-by-id of the SR and a referenced `Patient` (OPA Rule 4); negatives: no `_id` → 400, not-in-graph → 403 |
| `fulfiller.hurl` | token | **this node as fulfiller** — no-bearer `401`; Task create (1c), list/read (1a/1b), patch a patchable field (1d); negatives: non-patchable field → 400, non-owned patch → 403 |

### Auth source — mock or real

Token acquisition is pluggable (`tests/scripts/get-token.sh`); the **runner**
mints each scenario's token and passes it to Hurl, so the Hurl files never change.

- **`TOKEN_SOURCE=mock`** (default) — mint from the throwaway issuer with the
  *exact* claims a scenario needs. The gateway only needs discovery + JWKS to
  verify a signature (it runs `bearer_only` — no token endpoint), so `mock-auth`
  is a ~100-line Flask service serving discovery + JWKS + a claims-flexible
  `/token`. This tests exactly what the node does (validation + policy) and mocks
  away issuance, including the `private_key_jwt` exchange.
  **Never run `mock-auth` outside tests** — it signs any claims you ask for.
- **`TOKEN_SOURCE=real`** — run the base stack (no overlay) and:
  ```bash
  TOKEN_SOURCE=real CLIENT_ID=<l2-client> \
    CALLER_ORG=<client-org> OUR_ORG=<client-org> tests/scripts/run-tests.sh
  ```
  Tokens come from the real L2 flow (custodian `/sign` → exchange), with
  `fhirContext` supplied as RFC 9396 `authorization_details`. Note `scope` and
  `organization_reference` are then fixed by the **registered client**, so
  `CALLER_ORG` must equal that client's org (and the seeded Consent actor). Purely
  synthetic denials (wrong org, etc.) stay in the OPA unit tests.

### Seeding (test data lifecycle)

Production seeds only the **registry**; `clinical-orders` ships empty. `placer.hurl`
needs a `ServiceRequest` + `Patient` + `Consent`, so `run-tests.sh` seeds them via
the **internal `clinical-orders` proxy** (`:9091`, no auth) before the run and
removes them afterward (an `EXIT` trap). `fulfiller.hurl` creates its own Tasks
(tagged `identifier=urn:umzhc:test|e2e`); the teardown sweeps them. See
`tests/seed/` and `tests/scripts/seed.sh`.

### Configuration (env)

| Var | Default | Meaning |
|-----|---------|---------|
| `TOKEN_SOURCE` | `mock` | `mock` (issuer) or `real` (L2 flow) |
| `GATEWAY_URL` | `http://localhost:9081` | external gateway |
| `REGISTRY_URL` | `http://localhost:9084` | registry proxy |
| `PROXY_URL` | `http://localhost:9091` | internal clinical-orders proxy (seeding) |
| `CUSTODIAN_URL` | `http://localhost:9087` | key custodian |
| `OPA_URL` | `http://localhost:9181` | OPA |
| `MOCK_AUTH_URL` | `http://localhost:9099` | mock issuer `/token` |
| `CLIENT_ID` | `fulfiller-client-l2` | L2 client id (`real` only) |
| `CALLER_ORG` | `…/Organization/HospitalA` | placer: reading org = Consent actor |
| `OUR_ORG` | `…/Organization/HospitalB` | fulfiller: Task owner |
| `SR_ID` / `PAT_ID` | `sr-e2e` / `pat-e2e` | seeded fixture ids |
