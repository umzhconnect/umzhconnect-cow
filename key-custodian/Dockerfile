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

ARG BUILD_INSECURE=
RUN pip install --no-cache-dir \
    ${BUILD_INSECURE:+--trusted-host pypi.org --trusted-host files.pythonhosted.org} \
    flask==3.0.3 pyjwt==2.9.0 cryptography==43.0.1 requests==2.32.3

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 8000

# Plain CPython server is fine for the sandbox — single worker, no concurrency
# pressure. Production would front this with gunicorn/uvicorn.
CMD ["python", "/app/app.py"]
