#!/bin/sh
# =============================================================================
# Load every FHIR Mapping Language map in $MAPS_DIR into matchbox.
#
# Each <name>.fml is PUT to StructureMap/<name> as text/fhir-mapping: matchbox
# compiles it and stores it under the canonical declared in the map. PUT (not
# POST) is idempotent — re-running replaces the map instead of creating a second
# StructureMap with the same canonical.
#
# matchbox keeps maps loaded this way in its engine's MEMORY only (not in its
# Postgres database), so every matchbox restart drops them. Two modes:
#
#   one-shot (WATCH_INTERVAL unset): wait until matchbox is ready, load every
#     map once, exit non-zero on the first failure.
#   watch (WATCH_INTERVAL=<seconds>): run forever, as the sidecar in the matchbox
#     pod (matchbox.yaml). Every interval, once matchbox is ready, PUT a map
#     again when it is missing (matchbox restarted) or its .fml changed (the
#     mounted ConfigMap was updated). Failures are logged and retried on the next
#     round. $STATE_DIR/ready exists while every map is loaded — the sidecar's
#     readinessProbe — so the pod only takes traffic once the maps are there.
#
#   Env: MATCHBOX_URL      matchbox FHIR base (…/matchboxv3/fhir)
#        MAPS_DIR          directory holding the .fml files (default /maps)
#        WAIT_FOR_PROFILE  optional StructureDefinition canonical that must be
#                          installed before loading (= IG install finished)
#        WAIT_SECONDS      one-shot: how long to wait for matchbox (default 1800)
#        WATCH_INTERVAL    seconds between checks; set = watch mode
#        STATE_DIR         watch: checksums + ready marker (default /tmp/load-maps)
# =============================================================================
set -eu

BASE="${MATCHBOX_URL:?MATCHBOX_URL is required}"
MAPS_DIR="${MAPS_DIR:-/maps}"
WAIT_FOR_PROFILE="${WAIT_FOR_PROFILE:-}"
WAIT_SECONDS="${WAIT_SECONDS:-1800}"
WATCH_INTERVAL="${WATCH_INTERVAL:-}"
STATE_DIR="${STATE_DIR:-/tmp/load-maps}"
mkdir -p "$STATE_DIR"

# /metadata answers as soon as the server is up — but on first boot matchbox is
# then still installing the IG closure in the background. If WAIT_FOR_PROFILE is
# set, also wait until that profile is searchable, so the map PUT (and its
# engine reload) doesn't race the install.
ready() {
  curl -fsS --max-time 10 -o /dev/null "$BASE/metadata" 2>/dev/null || return 1
  [ -z "$WAIT_FOR_PROFILE" ] && return 0
  curl -fsS --max-time 10 "$BASE/StructureDefinition?url=$WAIT_FOR_PROFILE&_summary=count" 2>/dev/null \
    | tr -d '\n ' | grep -q '"total":[1-9]'
}

# PUT one map. The PUT triggers matchbox's engine reload (onlyOneEngine) — it
# can take minutes, so no --max-time here.
load_map() {
  map="$1"; id="$(basename "$map" .fml)"
  echo ">> loading $map -> StructureMap/$id"
  code="$(curl -sS -o "$STATE_DIR/response.json" -w '%{http_code}' -X PUT "$BASE/StructureMap/$id" \
    -H 'Content-Type: text/fhir-mapping' \
    -H 'Accept: application/fhir+json' \
    --data-binary @"$map")" || code=000
  case "$code" in
    200|201) echo ">> StructureMap/$id loaded (HTTP $code)" ;;
    *) echo "loading $id failed (HTTP $code):" >&2; cat "$STATE_DIR/response.json" >&2 2>/dev/null; echo >&2; return 1 ;;
  esac
}

maps() {
  found=0
  for map in "$MAPS_DIR"/*.fml; do
    [ -f "$map" ] || continue
    found=1; echo "$map"
  done
  [ "$found" = 1 ] || { echo "no .fml files in $MAPS_DIR" >&2; return 1; }
}

# ── watch mode (sidecar) ─────────────────────────────────────────────────────
if [ -n "$WATCH_INTERVAL" ]; then
  echo ">> watching $MAPS_DIR -> $BASE every ${WATCH_INTERVAL}s${WAIT_FOR_PROFILE:+ (once $WAIT_FOR_PROFILE is installed)}"
  rm -f "$STATE_DIR/ready"
  while :; do
    if ! ready; then
      # matchbox down, (re)starting or still installing the IGs: its maps are
      # gone or about to be, so stop advertising ready until they're back.
      rm -f "$STATE_DIR/ready"
    else
      all_loaded=1
      for map in $(maps || true); do
        id="$(basename "$map" .fml)"
        sum="$(cksum < "$map")"
        last="$(cat "$STATE_DIR/$id.cksum" 2>/dev/null || true)"
        present="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$BASE/StructureMap/$id" 2>/dev/null || true)"
        if [ "$present" != 200 ]; then
          echo ">> StructureMap/$id missing (HTTP $present) — matchbox restarted?"
          rm -f "$STATE_DIR/ready"
        elif [ "$sum" = "$last" ]; then
          continue
        else
          echo ">> $map changed (or not loaded by this sidecar yet)"
        fi
        if load_map "$map"; then echo "$sum" > "$STATE_DIR/$id.cksum"; else all_loaded=0; fi
      done
      [ -n "$(maps 2>/dev/null)" ] || all_loaded=0
      if [ "$all_loaded" = 1 ]; then
        [ -f "$STATE_DIR/ready" ] || echo ">> all maps loaded"
        touch "$STATE_DIR/ready"
      else
        rm -f "$STATE_DIR/ready"
      fi
    fi
    sleep "$WATCH_INTERVAL"
  done
fi

# ── one-shot mode ────────────────────────────────────────────────────────────
echo ">> waiting for matchbox at $BASE${WAIT_FOR_PROFILE:+ with $WAIT_FOR_PROFILE installed} (up to ${WAIT_SECONDS}s)"
waited=0
until ready; do
  [ "$waited" -ge "$WAIT_SECONDS" ] && { echo "matchbox not ready after ${WAIT_SECONDS}s" >&2; exit 1; }
  sleep 10
  waited=$((waited + 10))
done

for map in $(maps); do
  load_map "$map" || exit 1
done
