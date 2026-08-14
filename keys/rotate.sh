#!/usr/bin/env bash
# =============================================================================
# rotate.sh <new-kid> [old-kid] — start an L2 key rotation.
#
# Generates a fresh keypair with a NEW kid and prints the three-phase, GitOps
# rotation runbook tailored to it. It does NOT touch the cluster or git and does
# NOT do the whole rotation — rotation spans multiple commits with waits for the
# auth server to re-fetch the JWKS (see key-custodian/SEALED-SECRETS.md). This
# just does the mechanical prep + the exact per-phase steps.
#
#   keys/rotate.sh l2-2026-08          # rotate the default kid (l2) → l2-2026-08
#   keys/rotate.sh l2-2026-08 l2-old   # be explicit about the current (old) kid
#
# Run from the repo root.
# =============================================================================
set -euo pipefail

KEYS_DIR="$(cd "$(dirname "$0")" && pwd)"

NEW_KID="${1:-}"
OLD_KID="${2:-l2}"   # the kid currently in key-custodian-config (default: l2)
if [ -z "$NEW_KID" ]; then
  echo "usage: keys/rotate.sh <new-kid> [old-kid]   e.g. keys/rotate.sh l2-2026-08 l2" >&2
  exit 1
fi
if [ "$NEW_KID" = "$OLD_KID" ]; then
  echo "error: new-kid must differ from old-kid ('$OLD_KID') — never reuse a kid." >&2
  exit 1
fi

NEW_KEY="keys/${NEW_KID}.key"
NEW_JWKS="keys/${NEW_KID}.jwks.json"

echo "▶ generating new L2 keypair (kid=${NEW_KID})…"
"$KEYS_DIR/gen-keys.sh" "$NEW_KID"
echo

echo "── New public JWK — add this object to the key-custodian-jwks ConfigMap 'keys' array ──"
if command -v jq >/dev/null 2>&1; then
  jq '.keys[0]' "$KEYS_DIR/${NEW_KID}.jwks.json"
else
  echo "(jq not found — copy the single object inside \"keys\": [ … ] from ${NEW_JWKS})"
  cat "$KEYS_DIR/${NEW_KID}.jwks.json"
fi
echo

cat <<EOF
════════════════════════════════════════════════════════════════════════════════
 Rotation runbook  (kid ${OLD_KID} → ${NEW_KID})
 Full detail: key-custodian/SEALED-SECRETS.md   ·  nothing here touches the cluster
════════════════════════════════════════════════════════════════════════════════

PHASE 1 — publish the NEW public key; keep signing with the OLD (${OLD_KID})
  1. key-custodian/key-custodian.yaml → add the JWK above to the
     key-custodian-jwks ConfigMap so "keys" holds BOTH ${OLD_KID} and ${NEW_KID}.
     Leave KID in key-custodian-config unchanged (${OLD_KID}).
  2. git commit && git push   → ArgoCD rolls the pod; it now serves both keys.
  3. WAIT for the auth server to re-fetch the JWKS (≥ its cache TTL, or ask the
     steward to refresh) BEFORE Phase 2.

PHASE 2 — switch SIGNING to the new key (${NEW_KID})
  1. Seal the NEW private key into the key-custodian-l2 Secret:
       kubectl create secret generic key-custodian-l2 --namespace key-custodian \\
         --from-file=private.key=${NEW_KEY} --dry-run=client -o yaml \\
       | kubeseal --cert sealed-secrets-pub.pem --format yaml \\
         > key-custodian/key-custodian-l2-sealedsecret.yaml
  2. key-custodian-config ConfigMap → set  KID: "${NEW_KID}"
  3. git commit && git push   → restart. Smoke-test: mint a token via the Auth flow.
     If it FAILS → git revert this commit (the old key is still published → recovers).

PHASE 3 — retire the OLD key (${OLD_KID}), AFTER the overlap window
  (≥ JWKS cache TTL AND ≥ max assertion lifetime, so nothing verifies with ${OLD_KID})
  1. Remove the ${OLD_KID} JWK from the key-custodian-jwks ConfigMap ("keys" → [${NEW_KID}] only).
  2. rm keys/${OLD_KID}.key keys/${OLD_KID}.jwks.json
  3. git commit && git push   → restart.

⚠  ${NEW_KEY} is a PRIVATE key — never commit it (keys/*.key is gitignored).
════════════════════════════════════════════════════════════════════════════════
EOF
