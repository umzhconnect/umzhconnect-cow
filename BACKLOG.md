# Backlog

Tracked improvements that are deliberately deferred (not functional gaps).

## KMS/HSM-backed signing for the key-custodian

**Status:** deferred. **Area:** `key-custodian/app.py`.

The custodian **loads the L2 private key from a PEM** (`KEY_PATH`) and signs the
`private_key_jwt` assertion **in-process**. So the raw key exists in plaintext at
generation time (openssl/`gen-keys.sh` on a laptop/CI) and at rest as a cluster
Secret — its safety rests on machine hygiene + RBAC.

**Improvement:** delegate signing to a KMS/HSM (AWS KMS / GCP KMS / Azure Key
Vault / hardware HSM). The key is generated inside the module, is **non-exportable**,
and the app calls the KMS *Sign* API — so the private key never materialises in the
pod, git, or a Secret. Adds audit logging, IAM gating, and FIPS-validated hardware
(relevant for health data). Requires refactoring `app.py` to sign via the KMS SDK
instead of reading `KEY_PATH`, and dropping the private-key Secret mount (the JWKS
ConfigMap stays). See `key-custodian/SEALED-SECRETS.md` (#why-kms-beats-openssl).
Until then, Sealed Secrets is the right GitOps mechanism for the file-based key.

## Token caching in the key-custodian /token broker

**Status:** deferred. **Area:** `key-custodian/app.py`.

`/token` performs a **fresh** `client_credentials` exchange at the auth server on
**every** call. Under load (e.g. a workflow engine firing many runs) that is N
exchanges for N requests, all effectively identical for a given scope.

**Improvement:** cache the AS access token keyed by `(scope, ...)` and reuse it
until it is within a small skew of `expires_in`, so repeat calls are served from
memory. Mint fresh (bypass the cache) whenever the request carries
`authorization_details` (RFC 9396) — that token is request-specific and must not
be shared. Add a `TOKEN_CACHE_SKEW` env for the refresh margin. Keep the response
`Cache-Control: no-store` regardless (the cache is internal to the broker).

## Per-caller authentication on the key-custodian /token endpoint

**Status:** deferred. **Area:** `key-custodian/app.py`, `key-custodian/key-custodian.yaml`.

`/token` is **unauthenticated** (demo posture, same as the removed `/sign`): any
workload that can reach the Service can obtain an access token for this party's
client. It is mitigated today only by network scope — ClusterIP-only Service, no
ingress, and a NetworkPolicy is expected to fence it.

**Improvement:** gate `/token` with **workload identity** — the caller presents
its Kubernetes ServiceAccount token (audience-bound projected token) or a SPIFFE
SVID; the custodian verifies it (e.g. `TokenReview` / OIDC validation) and maps
the caller to an allowed `client_id`/scope policy, so a compromised workload
cannot widen its own access. mTLS between caller and custodian is an alternative.
Pair with a NetworkPolicy restricting who can even open the connection.

## OPA-side JWT signature verification (trust hardening)

**Status:** deferred. **Area:** `opa/policies/gateway.rego`.

Today `gateway.rego` **decodes** the bearer with `io.jwt.decode` but does **not
verify the signature** — it authorizes on the token's claims and trusts that the
calling Policy Enforcement Point already authenticated the token:

- **APISIX** validates the JWT via its `openid-connect` plugin (JWKS) before the
  `opa` plugin runs.
- **MuleSoft** validates the token in its own flow before forwarding to OPA.

This is a **trust topic**, not a functional gap: with the current consumers the
token is always authenticated upstream, and OPA's decision endpoint is only
reachable by trusted PEPs (ingress scoped to `/v1/data/umzh/authz/gateway` + edge
auth). But it means a consumer that *forgot* to validate, or any caller that got
network access to OPA, could get decisions on **forged claims**.

**Improvement:** make OPA self-contained — verify the signature in `gateway.rego`
with `io.jwt.decode_verify` against the auth server's JWKS, so authorization never
rests on unverified claims regardless of the consumer.

Considerations when implementing:
- OPA needs the JWKS: either fetch it from the auth server's discovery/`jwks_uri`
  via `http.send` (with `cache`) — mirroring what APISIX `openid-connect` does — or
  mount it as a data document (simpler, but manual rotation).
- It double-validates on the APISIX path (openid-connect already verified) — cheap
  and harmless.
- Decide on `iss` / `aud` / `exp` constraints in the verify step (align with the
  gateway's openid-connect config).
