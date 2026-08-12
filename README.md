# umzhconnect-cow

Everything **one hospital** runs to be a compatible UMZH Connect ecosystem
partner. Shared infrastructure — the **auth server**, the **mCSD registry**, and
the **partner** itself — is *external* and supplied via `.env`; it is never
deployed here.

This is a **self-contained** single-party deployment: the external gateway
(config + plugins), the OPA policies, and the key-custodian all live in this
repo. It was forked from the two-party UMZH Connect sandbox; policy/gateway
changes there are reconciled here manually. This node's env-specific data is
rendered from `.env` at startup, and its L2 signing key is generated locally
(`keys/gen-keys.sh`), never committed.

## What runs here (party-owned)

| Service | Role |
|---|---|
| `apisix-external` | External API gateway — JWT auth + OPA policy in front of `clinical-orders-fhir`. Runs the same standalone config as the k8s gateway (`clinical-orders/apisix/`); auth/OPA URLs from env. |
| `opa` | Consent / fhirContext policy engine (party-local Rego in `opa/policies/`). |
| `hapi-fhir` | The party's partitioned FHIR store (base), backed by a **managed (external) Postgres** — see below. Partitions: `clinical-orders` (this party's data, acts as fulfiller) and `registry` (mCSD directory). Internal only — reached via the proxies below. |
| `clinical-orders-fhir` | Outward, **partition-less** FHIR proxy for this party's `clinical-orders` partition (mirrors the k8s proxy). Maps `/fhir/*` → base `/fhir/clinical-orders/*` and strips the partition out of self-links/`Location`. |
| `registry-fhir` | Outward, **partition-less** mCSD proxy for the `registry` partition (mirrors the k8s proxy). Maps `/fhir/*` → base `/fhir/registry/*` and strips the partition out. |
| `key-custodian` | Holds the party's L2 private key; signs `private_key_jwt` assertions and serves the JWK Set. |
| `clinical-orders-init` | One-shot (owned by `clinical-orders/`): create this party's empty `clinical-orders` partition on the base HAPI. |
| `registry-seed` | One-shot (owned by `registry/`): create the `registry` partition and merge the mCSD directory from `registry/registry-bundle.json`. |

### Service folders

Each service owns its config/templates and (where applicable) its Kubernetes
manifests, so the same asset serves both docker compose and k8s:

| Folder | Holds |
|---|---|
| `hapi-fhir/` | base HAPI `application.yaml` + k8s manifests |
| `clinical-orders/` | FHIR proxy template, partition init, the APISIX external gateway (`clinical-orders/apisix/`), k8s manifests |
| `registry/` | FHIR proxy template, registry seed + bundle, k8s manifests |
| `opa/` | `policies/` (party-local rego) + static `opa-config.json` — see `opa/README.md` |
| `key-custodian/` | L2 assertion signer + JWKS publisher (build context) — see `key-custodian/README.md` |
| `keys/` | `gen-keys.sh` generates this node's L2 signing key (gitignored) — see `keys/README.md` |
| `tests/` | Hurl integration suite + runner — see `tests/README.md` |
| `requests/` | Bruno collection of sample requests — see `requests/README.md` |

## Managed database (external)

HAPI FHIR connects to a **managed Postgres** that is *not* deployed
here — the node has no `postgres` container. Connection details come from `.env`
(`DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USERNAME`/`DB_PASSWORD`) and are consumed by
`hapi-fhir/application.yaml` (via `${DB_*}` placeholders). Defaults target a local
Postgres (`hapi_fhir`, owner `umzhconnect`) reached from containers via
`host.docker.internal`.

> A container connecting over `host.docker.internal` reaches Postgres as a TCP
> client from the Docker bridge subnet — the host's `pg_hba.conf` must permit
> password (md5/scram) logins for that subnet, otherwise the connection is
> rejected.

The **partition layout** is created at seed time on the managed instance:

| Partition | Contents |
|---|---|
| `clinical-orders` | This party's clinical data (acts as the fulfiller). Created empty; records arrive at runtime. |
| `registry` | mCSD `Organization`/`Endpoint`/`HealthcareService` directory for `placer` and `fulfiller`, merged (PUT/upsert) from `registry/registry-bundle.json`. |

### Partition-less proxies

The base HAPI is URL-partitioned (`/fhir/{partition}/…`), but that segment must
not leak outward. Two nginx proxies front the base and expose **partition-less**
FHIR:

| Service | Host port (default) | Maps to base partition |
|---|---|---|
| `clinical-orders-fhir` | `CLINICAL_ORDERS_FHIR_PORT` (9091) | `clinical-orders` |
| `registry-fhir` | `REGISTRY_FHIR_PORT` (9084) | `registry` |

Each rewrites inbound `/fhir/*` onto `/fhir/<partition>/*`, and strips the
partition back out of response bodies (`sub_filter`) **and** the `Location`
header (`proxy_redirect`); the duplicate `Content-Location` header is dropped.
The proxy config is the shared `<service>/<service>-proxy.conf.template`, rendered
at container start by the nginx image's built-in envsubst from `PROXY_UPSTREAM`
(base host:port = `HAPI_BASE_UPSTREAM`), `PROXY_OUTWARD_URL` (= `*_FHIR_URL`, the
outward base the proxy advertises — keep it equal to the reachable host:port), and
`PROXY_INTERNAL_BASE` (the base URL HAPI stamps into self-links, i.e. its
`server_address`/`FHIR_SERVER_ADDRESS`). The rewrites key off `PROXY_INTERNAL_BASE`,
so it **must** equal whatever HAPI advertises: leave the sentinel default
(`http://localhost:8090/fhir`) when HAPI is fronted only by these proxies, and set
it to the base's real advertised URL when the base is *also* exposed directly (e.g.
via `hapi-fhir-ingress`) — otherwise the host is stripped of its partition but not
rewritten to the outward URL.

**Optional backend auth (clinical-orders only).** If the backend FHIR store
requires credentials (e.g. a commercial server behind the proxy), set
`PROXY_BACKEND_AUTHORIZATION` to the full `Authorization` header value —
`Basic <base64(user:pass)>` — and the clinical-orders proxy injects it on the
upstream request, overwriting the caller's own `Authorization` (which it does not
forward to the backend). Empty (the default) disables it: the caller's header
passes through untouched. It's a `PROXY_*` env (`.env`/compose) or Deployment env
(k8s, ideally from a Secret); the registry proxy has no such injection.

```bash
curl http://localhost:9084/fhir/Organization        # registry, no partition in URL
curl http://localhost:9091/fhir/Task                 # this party's clinical-orders
```

## Layout & Kubernetes

Each of the three cross-cutting services lives in a **self-contained top-level
folder** holding both its Kubernetes manifests *and* the shared assets docker
compose consumes — one file, two consumers:

| Folder | Namespace | Shared asset(s) (used by compose **and** k8s) | Manifests |
|---|---|---|---|
| `hapi-fhir/` | `hapi-fhir` | `application.yaml` | base HAPI Deployment/Service, `managed-postgres` ExternalName |
| `clinical-orders/` | `clinical-orders` | `clinical-orders-proxy.conf.template`, `create-partition.sh` | proxy Deployment/Service, ingress, hello-world, `clinical-orders-init` Job |
| `registry/` | `registry` | `registry-proxy.conf.template`, `seed-registry.sh`, `registry-bundle.json` | proxy Deployment/Service, ingress, `registry-seed` Job |

The base HAPI (namespace `hapi-fhir`) is ClusterIP-only; the proxies (their own
namespaces) reach it at `hapi-fhir.hapi-fhir.svc.cluster.local:8080`. Each service
**owns its own partition**: `clinical-orders-init` creates this party's empty data
partition, `registry-seed` creates the registry partition and merges its directory.
The base does no seeding.

**One source of truth.** Nothing is duplicated between compose and k8s. Because
each shared file sits *inside* its service folder, that folder's `kustomization.yaml`
generates its ConfigMap from the local file — no `..` escaping, so kubectl's
built-in kustomize accepts it with no `--load-restrictor` flag:

```yaml
# registry/kustomization.yaml
configMapGenerator:
  - name: registry-proxy-tpl                       # nginx template -> /etc/nginx/templates/
    files: [default.conf.template=registry-proxy.conf.template]
  - name: registry-seed                            # seed Job inputs
    files: [seed-registry.sh, registry-bundle.json]
# hapi-fhir/ generates hapi-fhir-config from application.yaml; clinical-orders/
# generates its proxy template + clinical-orders-init (create-partition.sh).
```

The proxy `.conf.template` is the *same* file compose mounts; k8s supplies the
`PROXY_UPSTREAM`/`PROXY_OUTWARD_URL` values (the k8s equivalents of the `.env`
entries) as Deployment env. Set `externalName` in `hapi-fhir/managed-db.yaml` to
your real managed DB host (move the password to a Secret if it has one).

> **Build/apply from `umzhconnect-cow/`:**
> `kubectl apply -k umzhconnect-cow/` (preview: `kubectl kustomize umzhconnect-cow/`).

**Pod Security (`restricted`).** Every workload sets the `restricted`
`securityContext` (`runAsNonRoot`, non-zero `runAsUser`, `allowPrivilegeEscalation:
false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`). Two images
were chosen to run non-root under that policy: the proxies use
`nginxinc/nginx-unprivileged` (UID 101, listens on 8080) and the seed/init Jobs use
`curlimages/curl` (curl baked in, so no root-only `apk add`). HAPI runs as UID
10001. This applies to the k8s manifests only — docker compose has no admission
controller and keeps the simpler `nginx:alpine`/`alpine` images.

## What is external (from `.env`)

| `.env` key | Meaning |
|---|---|
| `AUTH_SERVER_URL` + `AUTH_SERVER_REALM` | The ecosystem OIDC provider. Issues all tokens; the gateways validate against its discovery/JWKS. |
| `PARTNER_EXTERNAL_URL` | The partner hospital's external gateway (cross-party reads/writes go here directly). |
| `REGISTRY_URL` | The shared mCSD Organization/Endpoint registry. |

## Prerequisite: register this party in the auth server

Because the auth server is shared (a steward/central concern), this node assumes
its L2 client already exists there — it deploys **no** Keycloak and no
provisioner. The client (`L2_CLIENT_ID`) must be configured with:

- `clientAuthenticatorType: client-jwt`
- `use.jwks.url = true`
- `jwks.url = <OWN_EXTERNAL_URL>/jwks.json` ← the auth server fetches the party's
  public key from this node's external gateway to verify its assertions
- SMART system scopes (e.g. `system/Task.s`) and the `organization_reference`
  claim — these, not a realm role, are what the OPA policy authorizes on

`OWN_EXTERNAL_URL` therefore must be the URL the auth server **and** the partner
can actually reach this node's external gateway on.

## Run

```bash
# 1) generate this party's L2 signing key (once; *.key is gitignored)
keys/gen-keys.sh l2                     # writes keys/l2.{key,jwks.json}, kid=l2

# 2) configure
cp .env.example .env
# edit .env — at minimum PARTY, the AUTH_SERVER/PARTNER/REGISTRY URLs, and
# OWN_EXTERNAL_URL (must match the jwks.url registered above)

# 3) run
docker compose up -d --build
```

Verify the node itself:

```bash
curl http://localhost:${EXTERNAL_GATEWAY_PORT}/jwks.json     # public JWK Set
curl http://localhost:${KEY_CUSTODIAN_PORT}/healthz          # custodian identity
```

Or run the integration suite. It bundles a throwaway mock auth issuer (test
overlay) so tokens validate without a real auth server:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build
tests/scripts/run-tests.sh
```

`tests/` is an assert-checked Hurl suite — health, registry read-only, auth
negatives, plus a **placer** scenario (authorized ServiceRequest + referenced
reads) and a **fulfiller** scenario (Task create/update); it seeds the few
records the placer scenario needs and removes them afterward. `requests/` is a
Bruno collection for manual exploration. See `tests/README.md` and
`requests/README.md`.

A cross-party read then flows: this party's caller → mint an M2M token at the
auth server (assertion signed by `key-custodian`, fhirContext via RFC 9396
`authorization_details`) → call `PARTNER_EXTERNAL_URL` directly. No internal
proxy is involved.

## Trying it against the sandbox

The `.env.example` defaults point at the running root sandbox as the "external"
ecosystem (`host.docker.internal:8180` auth, `:8084` registry, `:8081` partner)
and deploy this node **as the fulfiller**, reusing the committed
`fulfiller-client-l2` key. Because the JWK Set is the same committed key the
sandbox already registered, the sandbox Keycloak can verify assertions this
node's custodian signs. Set distinct host ports (defaults: 9080/9081/9090/…) so
it can run alongside the sandbox.

## Notes / limitations

- **Registry seed** lives at `registry/registry-bundle.json` (`placer` + `fulfiller`
  Organizations, their Endpoints, and HealthcareServices), seeded by the registry
  service. The `clinical-orders` partition is intentionally seedless — it holds
  this party's runtime data.
- **DB credentials** are never baked into `hapi-fhir/application.yaml` — it is pure
  `${DB_*}` placeholders. Values come from `.env` (compose) or the
  `managed-db-config` ConfigMap / a Secret (k8s). The `managed-postgres`
  ExternalName Service is optional (see `hapi-fhir/managed-db.yaml`).
- **Single external gateway.** `apisix-external` (JWT auth + OPA policy) fronts the
  `clinical-orders-fhir` proxy, which maps to the `clinical-orders` partition. It
  runs the k8s gateway's standalone config from `clinical-orders/apisix/`. The
  internal gateway and the old `nginx-proxy` self-link rewriter have been removed
  (the per-partition proxies self-rewrite); OPA's `fhir_base`
  (`opa/opa-config.json`) now points at the base HAPI's `clinical-orders`
  partition directly.
- **No central `config/`.** Env-specific config is rendered per service (nginx
  images self-render their templates). OPA loads a static data document
  (`opa/opa-config.json`) — no render step.
- **SMART-scope + context-centric authz.** Access is decided entirely by SMART
  system scopes plus the token's `organization_reference` and consent /
  fhirContext graph (`opa/policies/main.rego`); there is no coarse realm-role
  gate. Multi-partner support comes from the registry + consent, not an allow-list.
- **Fully self-contained.** The gateway (config + plugins), the OPA policies, and
  the **key-custodian** (`key-custodian/`) are all vendored here — nothing is
  referenced from outside the repo. The custodian's L2 signing key is generated
  locally by `keys/gen-keys.sh` and mounted from `./keys/l2.*`; the
  private key is gitignored (see `keys/README.md`). This was forked from the
  two-party sandbox — reconcile policy/gateway changes across the two manually.
