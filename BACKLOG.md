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
