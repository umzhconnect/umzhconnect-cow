# Providing the L2 private key with Sealed Secrets (GitOps, no cluster access)

Production guide for delivering the key-custodian's **L2 private key** through git
only — no `kubectl` against the cluster. The private key is sealed (encrypted) and
committed; the **public JWKS** is a plain ConfigMap; ArgoCD + the in-cluster
sealed-secrets controller do the rest.

```
you (no cluster access)                          cluster (platform-managed)
  keys/gen-keys.sh l2  ─┐
  kubeseal --cert  ─────┤ SealedSecret (encrypted) ─► git ─► ArgoCD ─► controller ─► Secret key-custodian-l2
  edit jwks ConfigMap ──┘ ConfigMap (public jwks)  ─► git ─► ArgoCD ─────────────────► key-custodian pod
```

## Roles

- **Platform team (has cluster access):** installs the Bitnami `sealed-secrets`
  controller and hands you its **public certificate** (`.pem`). That cert is a
  *public key* — safe to share. Also (recommended) installs **Reloader** for
  rotation.
- **You (app team, no cluster access):** `kubeseal` + `openssl` locally; commit to
  git; never touch the cluster.

> You cannot use `kubeseal --fetch-cert` (it hits the cluster API). You **must**
> obtain the cert out of band. Save it as `sealed-secrets-pub.pem`.

## 1. Generate (or obtain) the L2 keypair

```bash
keys/gen-keys.sh l2       # → keys/l2.key (private) + keys/l2.jwks.json (public)
```

For a production key, prefer a KMS/HSM over `openssl` — see **[Why KMS beats
openssl](#why-kms-beats-openssl-for-production)** below.

## 2. Seal ONLY the private key, offline, into a file

No plaintext ever hits disk (the pipe renders the Secret locally and seals it):

```bash
kubectl create secret generic key-custodian-l2 \
  --namespace key-custodian \
  --from-file=private.key=keys/l2.key \
  --dry-run=client -o yaml \
| kubeseal --cert sealed-secrets-pub.pem --format yaml \
  > key-custodian/key-custodian-l2-sealedsecret.yaml
```

- `--dry-run=client` renders the Secret **locally** — no cluster contact (it's the
  `kubectl` binary as a templater). No `kubectl` at all? Hand-write the Secret with
  `openssl base64 -A -in keys/l2.key` and pipe that to `kubeseal`.
- `--cert …` seals **offline** with the public key.
- Namespace + name must be `key-custodian` / `key-custodian-l2` — the default
  *strict* scope binds the SealedSecret to exactly that namespace+name. Re-seal if
  either ever changes.
- The output is encrypted with the controller's public key; **only the in-cluster
  controller can decrypt it**, so it is safe to commit.

## 3. Put the PUBLIC JWKS in the ConfigMap

The JWKS is public — commit it plainly. Copy the contents of your generated
`keys/l2.jwks.json` into the `key-custodian-jwks` ConfigMap in
[`key-custodian.yaml`](key-custodian.yaml) (replace the `n` placeholder; keep
`kid` = the `KID` in `key-custodian-config`). It must correspond to the sealed
private key.

## 4. Wire it in

In [`kustomization.yaml`](kustomization.yaml), uncomment:

```yaml
  - key-custodian-l2-sealedsecret.yaml
```

The Deployment already mounts a Secret named `key-custodian-l2` at `/secret` and
the ConfigMap at `/jwks` — no Deployment change needed.

## 5. Commit → ArgoCD → done

```bash
git add key-custodian/key-custodian-l2-sealedsecret.yaml \
        key-custodian/key-custodian.yaml \
        key-custodian/kustomization.yaml
git commit -m "key-custodian: L2 SealedSecret + public JWKS" && git push
```

ArgoCD applies the `SealedSecret`; the controller decrypts it in-cluster into
`Secret key-custodian-l2`; the pod mounts `private.key` from it and `jwks.json`
from the ConfigMap. All through git.

## Rotation (three-phase overlap, kubectl-free)

**Do not just swap the key.** The auth server verifies this party's
`private_key_jwt` assertion against the **JWKS it fetched and cached**. Switch the
signing key before the verifier has the new public key — or drop the old key too
early — and the party can't mint tokens. So rotate with an **overlapping dual-key**
process keyed by `kid`, as three git commits.

Principle:
- Every key gets a **unique `kid`** (e.g. `l2-2026-08`) — never reuse a `kid`.
- The **JWKS is an array**, so it carries the **old and new public keys at once**.
- Signing switches **atomically** (one private key at a time); the **JWKS** is what
  overlaps.
- Timing is driven by the **auth server's JWKS cache TTL** (confirm it with the
  auth-server steward) and the short assertion lifetime (`exp` ≈ 60s). Rotating this
  key only affects **minting new tokens** — already-issued access tokens are signed
  by the auth server, so they keep working.

Prerequisite — the pod must **restart to pick up ConfigMap/Secret changes** (the
app reads `KEY_PATH`/`JWKS_PATH` at startup). Either add
`reloader.stakater.com/auto: "true"` to the Deployment ([Reloader], ask the
platform team) so a change restarts the pod, **or** in each rotation commit bump a
pod-template annotation (e.g. `keyRotation: "2026-08"`) so ArgoCD rolls the pod.

[Reloader]: https://github.com/stakater/Reloader

> **Helper:** `keys/rotate.sh <new-kid> [old-kid]` generates the new keypair and
> prints this three-phase runbook filled in with your kids and file paths. It does
> no cluster/git actions — you still make the commits per phase.

### Phase 1 — publish the NEW public key; keep signing with the OLD

```bash
keys/gen-keys.sh l2-2026-08          # new keypair, NEW kid
```
- Add the new public JWK to the `key-custodian-jwks` ConfigMap in
  `key-custodian.yaml` → it now lists **[old, new]** (`kid` = `l2`, `kid` =
  `l2-2026-08`). `KID` in `key-custodian-config` is **unchanged** (still signs old).
- Commit & push → ArgoCD → the custodian restarts and serves **both** keys, still
  signing with the old one.
- **Wait** until the auth server has re-fetched the JWKS — at least its cache TTL
  (or have the steward force a refresh). Now the verifier knows both keys.

### Phase 2 — switch SIGNING to the new key

- Re-seal the **new** private key into `key-custodian-l2` (same Secret name, per
  step 2 above, using `keys/l2-2026-08.key`), and set `KID: "l2-2026-08"` in
  `key-custodian-config`. Commit both.
- ArgoCD → restart → the custodian now signs with the new key + new `kid`; the auth
  server verifies against the new JWK it already holds. JWKS still lists both.
- **Smoke-test:** run the Auth flow (mint a token) — it must succeed before you
  proceed.

### Phase 3 — retire the OLD key

- After the overlap window (≥ the JWKS cache TTL **and** ≥ the max assertion
  lifetime, so nothing verifies with the old key any more), remove the **old**
  public JWK from the `key-custodian-jwks` ConfigMap → **[new]** only, and delete
  the old sealed key material. Commit.
- ArgoCD → restart.

### Rollback

If Phase 2 breaks token minting, **`git revert` the Phase-2 commit** — the
custodian signs with the old key again, and because the old public JWK is still in
the JWKS (Phase 3 not done), verification recovers immediately. Publishing before
switching and retiring after switching is exactly what makes every step reversible.

### Emergency rotation (compromised key)

Skip the overlap for the bad key: **immediately drop the compromised public JWK
from the JWKS** (so the auth server rejects anything signed with it), publish +
switch to a fresh key, and **notify the auth-server steward** to revoke the client
/ invalidate tokens. You accept a brief window where in-flight old-key verification
fails — that's intended.

> With **KMS** (see below), rotation is simpler: publish the new public key in the
> JWKS, point signing at the new KMS key *version*, then disable the old version —
> no sealing, no key files, no Secret swaps.

## Hygiene

- **Never commit** `keys/l2.key` or any plaintext Secret (gitignored; the pipe
  avoids writing plaintext at all). Only the `.pem` public cert is needed to seal.
- The controller's **private sealing key** must be backed up by the platform team —
  if lost, no SealedSecret can be decrypted.
- The materialised `key-custodian-l2` Secret is base64, not encrypted, at rest in
  the cluster — anyone with `get secret` in the namespace can read the key. Lock it
  down with RBAC/NetworkPolicy (and see the KMS note below for removing this
  exposure entirely).

## Why KMS beats openssl for production

`openssl` (and `gen-keys.sh`) generate the private key on a **general-purpose
machine** (a laptop or CI runner). That means the raw key exists in plaintext there
— on disk, in memory, in shell history, in backups/swap, one `git add` away from a
leak — and later as a base64 `Secret` in the cluster. Its safety rests entirely on
the hygiene of those machines. And this key is **high value**: it *is* the party's
identity to the whole ecosystem — a leaked L2 key lets anyone mint assertions and
impersonate the party to request data.

A **KMS/HSM** (AWS KMS, GCP KMS, Azure Key Vault, or a hardware HSM) removes those
exposures:

- **Non-exportable keys.** The private key is generated *inside* the module and
  never leaves it in plaintext — there is no file to leak, seal, or commit.
- **Signing happens inside the boundary.** The custodian calls the KMS *Sign* API;
  the app never holds the key. Compromising the pod no longer leaks the key.
- **Hardware-backed + compliance.** FIPS 140-2/3-validated modules — often required
  for regulated / health-data environments.
- **Access control + audit.** IAM gates who/what may sign, and every signing
  operation is logged. A leaked laptop is no longer a full key compromise — you
  revoke IAM and/or rotate.
- **Managed rotation** without moving key material around.

Sealed Secrets protects the key **at rest in git** and hands it to the cluster —
good — but the key was still *born* in `openssl` and *lives* as a readable cluster
Secret. KMS eliminates both.

**Architectural note / follow-up:** the custodian today **loads a PEM and signs
in-process**, so realising the full KMS benefit (non-exportable key, sign-in-KMS)
means refactoring it to call the KMS Sign API instead of reading `KEY_PATH`. That's
tracked in [`../BACKLOG.md`](../BACKLOG.md). Until then, Sealed Secrets is the right
GitOps mechanism for a file-based key; a KMS/HSM is the target for the key's *origin
and custody*.
