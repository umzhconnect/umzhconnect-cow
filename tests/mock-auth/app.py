"""
mock-auth — a throwaway OIDC issuer for the integration tests.

It exists ONLY to let the external gateway validate bearer tokens without a real
auth server. The gateway's openid-connect plugin (bearer_only) needs just two
things to accept a token — a discovery document and the JWKS to check the
signature — and OPA then reads the claims off the (already-validated) token. So
this service:

    GET  /.well-known/openid-configuration   discovery (issuer + jwks_uri)
    GET  /jwks.json                          public JWK Set (RS256)
    GET  /healthz                            {"issuer", "kid"}
    POST /token                              mint an access token with the claims
                                             a test scenario asks for

POST /token body (all optional):
    {
      "scope": "system/Task.c system/Task.u",
      "organization_reference": "https://registry.example/Organization/Hosp",
      "fhirContext": [{"reference": "ServiceRequest/sr-e2e"}],
      "sub": "test-client",
      "ttl": 300
    }

The claims are shaped exactly how apisix.rego reads them: `scope` (string),
`extensions.umzhconnect.organization_reference`, and `fhirContext` (array).

NEVER run this outside tests — it signs any claims you ask for.
"""

import base64
import os
import time
import uuid

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

ISSUER = os.environ.get("ISSUER", "http://mock-auth:8080")
KID = os.environ.get("KID", "mock-auth")
PORT = int(os.environ.get("PORT", "8080"))
DEFAULT_TTL = int(os.environ.get("TOKEN_TTL", "300"))

# Fresh RSA keypair per process. The gateway fetches the JWKS after this service
# is up (it is recreated together with the overlay), so there is no stale-key window.
_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()


def _b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_pub = _key.public_key().public_numbers()
JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": _b64url_uint(_pub.n),
            "e": _b64url_uint(_pub.e),
        }
    ]
}

app = Flask(__name__)


@app.get("/.well-known/openid-configuration")
def discovery():
    return jsonify(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks.json",
            "response_types_supported": ["token", "id_token", "code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "grant_types_supported": ["client_credentials"],
        }
    )


@app.get("/jwks.json")
def jwks():
    return jsonify(JWKS)


@app.get("/healthz")
def healthz():
    return jsonify({"issuer": ISSUER, "kid": KID})


@app.post("/token")
def token():
    body = request.get_json(silent=True) or {}
    now = int(time.time())
    ttl = int(body.get("ttl", DEFAULT_TTL))
    claims = {
        "iss": ISSUER,
        "sub": body.get("sub", "test-client"),
        "aud": body.get("audience", "account"),
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
        "scope": body.get("scope", ""),
        "extensions": {
            "umzhconnect": {
                "organization_reference": body.get("organization_reference", "")
            }
        },
    }
    if body.get("fhirContext") is not None:
        claims["fhirContext"] = body["fhirContext"]

    access_token = pyjwt.encode(
        claims, PRIVATE_PEM, algorithm="RS256", headers={"kid": KID, "typ": "JWT"}
    )
    return jsonify(
        {"access_token": access_token, "token_type": "Bearer", "expires_in": ttl}
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
