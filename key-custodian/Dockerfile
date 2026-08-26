# Single-tenant key custodian / token broker. One image, instantiated once per
# party with CLIENT_ID/KID env + per-party key mount.
#
# Endpoints:
#   GET  /jwks.json   public JWK Set for the party this container belongs to
#   POST /token       run the private_key_jwt client_credentials flow at the auth
#                     server and return the access token (key never leaves here)
#   GET  /healthz     client_id + kid (for sanity probes)
#
# DEMO ONLY: /token has no authentication. Production would gate it with mTLS,
# a workload-identity token (k8s ServiceAccount / SPIFFE), or per-caller policy.
# See key-custodian/README.md.
FROM python:3.12-slim

# Patch the OS packages the base image ships with — clears Trivy's fixable
# Debian HIGH/CRITICAL — then drop the apt lists to keep the image small. Behind
# a corporate proxy, apt reads the same http_proxy/https_proxy env pip uses;
# Docker/BuildKit forwards those when set in the client or passed as build args.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# BUILD_INSECURE=1 relaxes pip's TLS host checks for a proxy presenting an
# untrusted cert (dev only). Pins chosen to clear Trivy's fixable Python HIGHs:
#   pyjwt 2.13.0        — CVE-2026-48526 (auth bypass), CVE-2026-32597 (crit hdr)
#   cryptography 50.0.0 — CVE-2026-26007, -69247, -69249, bundled-OpenSSL GHSA
ARG BUILD_INSECURE=
RUN pip install --no-cache-dir \
    ${BUILD_INSECURE:+--trusted-host pypi.org --trusted-host files.pythonhosted.org} \
    flask==3.0.3 pyjwt==2.13.0 cryptography==50.0.0 requests==2.32.3

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 8000

# Plain CPython server is fine for the sandbox — single worker, no concurrency
# pressure. Production would front this with gunicorn/uvicorn.
CMD ["python", "/app/app.py"]
