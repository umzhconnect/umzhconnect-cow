"""
Single-tenant token broker + JWK Set publisher.

The container holds exactly one party's private key and JWK Set, and it never
hands either the key OR the signed client assertion to a caller. Instead it runs
the `private_key_jwt` client-credentials exchange against the auth server itself
and returns only the resulting access token. The private key's blast radius is
this one component; callers receive a short-lived, scoped bearer token and
nothing else.

Per-party-ness comes from env + the mount source — the same image runs once per
party. There is no `/token/{party}` path: the container *is* the party.

Endpoints:
    GET  /jwks.json   public JWK Set (partner IdPs verify our assertions here)
    POST /token       run client_credentials (private_key_jwt) at the AS and
                      return the access token
    GET  /healthz     {"client_id": ..., "kid": ...}

POST /token request body (all fields optional):
    {
      "client_id":             "<override CLIENT_ID>",  # iss+sub+client_id
      "scope":                 "system/Task.s ...",     # default DEFAULT_SCOPE
      "authorization_details": [ ... ]                  # RFC 9396, forwarded as-is
    }

POST /token response (the AS token response, passed through verbatim):
    {
      "access_token": "<JWT>",
      "token_type":   "Bearer",
      "expires_in":   300,
      "scope":        "...",
      ...
    }

The assertion `aud` defaults to the token-endpoint URL (TOKEN_ENDPOINT) — per
RFC 7523 the private_key_jwt audience is normally the OAuth token endpoint — but
can be overridden with AUDIENCE when the auth server expects a different value.
Token caching and per-caller auth on /token are deferred (see BACKLOG.md).

Env contract:
    CLIENT_ID          required   default iss+sub+client_id (per-request overridable)
    KID                required   kid header (must match the JWK in JWKS_PATH)
    KEY_PATH           default /keys/private.key
    JWKS_PATH          default /keys/jwks.json
    TOKEN_ENDPOINT     required   the token endpoint the exchange is POSTed to
    AUDIENCE           default TOKEN_ENDPOINT       assertion `aud` claim
    DEFAULT_SCOPE      default ""                  scope requested when none given
    ASSERTION_TTL      default 60                  assertion lifetime (s), 1..300
    HTTP_TIMEOUT       default 10                  AS request timeout (s)
    TLS_VERIFY         default "true"              verify the AS TLS cert
    PORT               default 8000
"""

import json
import os
import time
import uuid

import jwt as pyjwt
import requests
from flask import Flask, jsonify, request


CLIENT_ID          = os.environ["CLIENT_ID"]
KID                = os.environ["KID"]
KEY_PATH           = os.environ.get("KEY_PATH",  "/keys/private.key")
JWKS_PATH          = os.environ.get("JWKS_PATH", "/keys/jwks.json")
# Where the client_credentials exchange is POSTed.
TOKEN_ENDPOINT     = os.environ["TOKEN_ENDPOINT"]
# The assertion `aud`. Per RFC 7523 the private_key_jwt audience is normally the
# token endpoint, so it defaults to TOKEN_ENDPOINT — set AUDIENCE only when the
# auth server expects a different value (e.g. the issuer URL).
AUDIENCE           = os.environ.get("AUDIENCE", TOKEN_ENDPOINT)
DEFAULT_SCOPE      = os.environ.get("DEFAULT_SCOPE", "")
ASSERTION_TTL      = int(os.environ.get("ASSERTION_TTL", "60"))
HTTP_TIMEOUT       = int(os.environ.get("HTTP_TIMEOUT", "10"))
TLS_VERIFY         = os.environ.get("TLS_VERIFY", "true").lower() != "false"
PORT               = int(os.environ.get("PORT", "8000"))

if not (1 <= ASSERTION_TTL <= 300):
    raise SystemExit("ASSERTION_TTL must be between 1 and 300 seconds")

# Read once at startup. If the key rotates on disk, restart the container.
with open(KEY_PATH, "r", encoding="utf-8") as fh:
    PRIVATE_KEY_PEM = fh.read()

with open(JWKS_PATH, "r", encoding="utf-8") as fh:
    JWKS = json.load(fh)

_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify({"client_id": CLIENT_ID, "kid": KID})


@app.get("/jwks.json")
def jwks():
    response = app.response_class(
        response=json.dumps(JWKS),
        status=200,
        mimetype="application/json",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _mint_assertion(client_id):
    """Build the RS256 private_key_jwt client assertion for this party."""
    now = int(time.time())
    return pyjwt.encode(
        {
            "iss": client_id,
            "sub": client_id,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + ASSERTION_TTL,
            "jti": str(uuid.uuid4()),
        },
        PRIVATE_KEY_PEM,
        algorithm="RS256",
        headers={"kid": KID, "typ": "JWT"},
    )


@app.post("/token")
def token():
    body = request.get_json(silent=True) or {}
    client_id = body.get("client_id", CLIENT_ID)
    scope = body.get("scope", DEFAULT_SCOPE)
    authorization_details = body.get("authorization_details")

    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": _ASSERTION_TYPE,
        "client_assertion": _mint_assertion(client_id),
    }
    if scope:
        data["scope"] = scope
    if authorization_details is not None:
        # RFC 9396 — the AS expects a JSON string for this form parameter.
        data["authorization_details"] = json.dumps(authorization_details)

    try:
        resp = requests.post(
            TOKEN_ENDPOINT,
            data=data,
            headers={"Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
            verify=TLS_VERIFY,
        )
    except requests.RequestException as exc:
        # AS unreachable / timed out — the caller should retry, not treat this as
        # an auth failure. Don't leak internal exception detail.
        app.logger.warning("token exchange to %s failed: %s", TOKEN_ENDPOINT, exc)
        return jsonify({"error": "auth_server_unreachable"}), 502

    if resp.status_code != 200:
        # Surface the AS's own OAuth error (invalid_client, invalid_scope, ...)
        # so the caller can see why, without inventing our own error shape.
        try:
            payload = resp.json()
        except ValueError:
            payload = {"error": "token_endpoint_error"}
        return jsonify(payload), resp.status_code

    response = jsonify(resp.json())
    response.headers["Cache-Control"] = "no-store"
    return response


if __name__ == "__main__":
    # Flask's dev server is enough for the sandbox; one worker, no autoreload.
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
