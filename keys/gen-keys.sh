#!/usr/bin/env bash
#
# gen-keys.sh — (re)generate a demo L2 RSA keypair and its JWK Set.
#
# Given a key basename (e.g. "l2"), generates a fresh RSA-2048 private
# key at keys/<name>.key and writes the matching public JWK Set at
# keys/<name>.jwks.json in one step — so the private key and the published JWKS
# can never drift apart. Run this once before `docker compose up`; the private
# key (*.key) is gitignored and never committed.
#
# The JWK `kid` is set to <name>, the same value the signer (the key-custodian)
# emits in the JWT header, so the auth server picks the right key during
# private_key_jwt verification.
#
# Only depends on openssl + standard coreutils (no python, no jq).
#
# Usage:
#   keys/gen-keys.sh l2        # basename must match L2_KID in your .env

set -euo pipefail

KEYS_DIR="$(cd "$(dirname "$0")" && pwd)"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

rotate() {
    name="$1"
    key="${KEYS_DIR}/${name}.key"
    out="${KEYS_DIR}/${name}.jwks.json"

    openssl genrsa -out "$key" 2048 2>/dev/null
    chmod 644 "$key"

    # Modulus: openssl prints it as hex (n), convert hex -> raw bytes -> base64url.
    n=$(openssl rsa -in "$key" -noout -modulus 2>/dev/null \
        | sed 's/Modulus=//' | xxd -r -p | b64url)
    # Public exponent is 65537 (AQAB) for openssl-generated RSA keys.
    e="AQAB"

    cat > "$out" <<EOF
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "${name}",
      "n": "${n}",
      "e": "${e}"
    }
  ]
}
EOF
    echo "  rotated ${name}: wrote ${key} + ${out} (kid=${name})"
}

if [ "$#" -eq 0 ]; then
    echo "Usage: keys/gen-keys.sh <key-basename> [<key-basename> ...]" >&2
    echo "  e.g. keys/gen-keys.sh l2" >&2
    exit 1
fi

for name in "$@"; do
    rotate "$name"
done
