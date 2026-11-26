# Throwaway OIDC issuer for integration tests only. Not for production.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
# BUILD_INSECURE=1 relaxes pip's TLS host checks for a proxy presenting an
# untrusted cert (dev only), as in key-custodian/Dockerfile.
ARG BUILD_INSECURE=
RUN pip install --no-cache-dir \
    ${BUILD_INSECURE:+--trusted-host pypi.org --trusted-host files.pythonhosted.org} \
    -r requirements.txt
COPY app.py .

EXPOSE 8080
CMD ["python", "app.py"]
