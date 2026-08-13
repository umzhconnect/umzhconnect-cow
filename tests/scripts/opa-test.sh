#!/bin/sh
# =============================================================================
# opa-test.sh — run the OPA policy unit tests. Hermetic: no stack, no auth, no
# HAPI (http.send is mocked in the tests). Uses the opa binary if present, else
# the openpolicyagent/opa image.
#
#   tests/scripts/opa-test.sh                 # verbose
#   tests/scripts/opa-test.sh --coverage      # + coverage report
# =============================================================================
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if command -v opa > /dev/null 2>&1; then
    exec opa test "${ROOT}/opa/policies" "${ROOT}/tests/opa" -v "$@"
else
    exec docker run --rm -v "${ROOT}:/w:ro" -w /w --entrypoint /opa \
        openpolicyagent/opa:0.70.0 test opa/policies tests/opa -v "$@"
fi
