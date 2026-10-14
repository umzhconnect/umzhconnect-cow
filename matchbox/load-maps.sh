#!/bin/sh
# =============================================================================
# Load every FHIR Mapping Language map in $MAPS_DIR into matchbox.
#
# Each <name>.fml is PUT to StructureMap/<name> as text/fhir-mapping: matchbox
# compiles it and stores it under the canonical declared in the map. PUT (not
# POST) is idempotent — re-running replaces the map instead of creating a second
# StructureMap with the same canonical.
#
#   Env: MATCHBOX_URL      matchbox FHIR base (…/matchboxv3/fhir)
#        MAPS_DIR          directory holding the .fml files (default /maps)
#        WAIT_FOR_PROFILE  optional StructureDefinition canonical that must be
#                          installed before loading (= IG install finished)
#        WAIT_SECONDS      how long to wait for matchbox (default 1800)
# =============================================================================
set -eu

BASE="${MATCHBOX_URL:?MATCHBOX_URL is required}"
MAPS_DIR="${MAPS_DIR:-/maps}"
WAIT_FOR_PROFILE="${WAIT_FOR_PROFILE:-}"
WAIT_SECONDS="${WAIT_SECONDS:-1800}"

# /metadata answers as soon as the server is up — but on first boot matchbox is
# then still installing the IG closure in the background. If WAIT_FOR_PROFILE is
# set, also wait until that profile is searchable, so the map PUT (and its
# engine reload) doesn't race the install.
ready() {
  curl -fsS -o /dev/null "$BASE/metadata" || return 1
  [ -z "$WAIT_FOR_PROFILE" ] && return 0
  curl -fsS "$BASE/StructureDefinition?url=$WAIT_FOR_PROFILE&_summary=count" \
    | tr -d '\n ' | grep -q '"total":[1-9]'
}

echo ">> waiting for matchbox at $BASE${WAIT_FOR_PROFILE:+ with $WAIT_FOR_PROFILE installed} (up to ${WAIT_SECONDS}s)"
waited=0
until ready; do
  [ "$waited" -ge "$WAIT_SECONDS" ] && { echo "matchbox not ready after ${WAIT_SECONDS}s" >&2; exit 1; }
  sleep 10
  waited=$((waited + 10))
done

for map in "$MAPS_DIR"/*.fml; do
  [ -f "$map" ] || { echo "no .fml files in $MAPS_DIR" >&2; exit 1; }
  id="$(basename "$map" .fml)"
  echo ">> loading $map -> StructureMap/$id"
  # The PUT triggers matchbox's engine reload (onlyOneEngine) — can take minutes.
  code="$(curl -sS -o /tmp/response.json -w '%{http_code}' -X PUT "$BASE/StructureMap/$id" \
    -H 'Content-Type: text/fhir-mapping' \
    -H 'Accept: application/fhir+json' \
    --data-binary @"$map")"
  case "$code" in
    200|201) echo ">> StructureMap/$id loaded (HTTP $code)" ;;
    *) echo "loading $id failed (HTTP $code):" >&2; cat /tmp/response.json >&2; exit 1 ;;
  esac
done
