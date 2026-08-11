#!/bin/sh
# =============================================================================
# create-partition — one-shot owned by the clinical-orders service: create this
# party's 'clinical-orders' data partition on the base HAPI. Left EMPTY; records
# arrive at runtime through the proxy. Shared by docker compose and the k8s
# clinical-orders-init Job. Idempotent (tolerates "already exists").
# =============================================================================
set -eu

FHIR_BASE="${FHIR_BASE:-http://hapi-fhir:8080/fhir}"
PARTITION="${PARTITION:-clinical-orders}"
PARTITION_ID="${PARTITION_ID:-1}"
MAX_RETRIES=60
RETRY_INTERVAL=5

echo "[clinical-orders-init] FHIR_BASE=${FHIR_BASE}"

# ── Wait for HAPI ────────────────────────────────────────────────────────────
i=0
while [ "$i" -lt "$MAX_RETRIES" ]; do
  if curl -sf "${FHIR_BASE}/DEFAULT/metadata" > /dev/null 2>&1; then
    echo "[clinical-orders-init] HAPI ready"; break
  fi
  i=$((i + 1)); echo "[clinical-orders-init] waiting for HAPI ($i/$MAX_RETRIES)…"; sleep "$RETRY_INTERVAL"
done
[ "$i" -lt "$MAX_RETRIES" ] || { echo "[clinical-orders-init] HAPI not ready"; exit 1; }

# ── Create the partition (idempotent) ────────────────────────────────────────
echo "[clinical-orders-init] creating partition '${PARTITION}' (id=${PARTITION_ID})…"
_code=$(curl -s -o /tmp/part.json -w "%{http_code}" -X POST \
  "${FHIR_BASE}/DEFAULT/\$partition-management-create-partition" \
  -H "Content-Type: application/fhir+json" \
  -d "{\"resourceType\":\"Parameters\",\"parameter\":[
        {\"name\":\"id\",\"valueInteger\":${PARTITION_ID}},
        {\"name\":\"name\",\"valueCode\":\"${PARTITION}\"},
        {\"name\":\"description\",\"valueString\":\"Clinical orders partition (this party — acts as fulfiller)\"}]}")
if [ "$_code" = "200" ] || [ "$_code" = "201" ]; then
  echo "  partition created (HTTP ${_code})"
elif [ "$_code" = "409" ] || { [ "$_code" = "400" ] && grep -q "already defined" /tmp/part.json; }; then
  echo "  partition already exists — skipping"
else
  echo "  WARNING: partition returned HTTP ${_code}: $(head -c 200 /tmp/part.json)"
fi

echo "[clinical-orders-init] done (partition left empty)."
