#!/usr/bin/env bash
#
# SAST: Semgrep over this repository's own Go code.
#
# The secret scan reads what was committed, the dependency scan reads what
# was imported, and this reads what was written here.
#
# Rulesets: p/golang and p/security-audit. Not p/secrets: gitleaks owns
# that question over the full history. --error makes this a gate.
#
# Exceptions are per-rule, per-line nosemgrep comments in the source, each
# with its reason. Never a disabled ruleset and never a path exclusion,
# which would exempt every future finding in that file too.
#
#   ci/scan-code.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

# --metrics=off: no telemetry. --exclude=.local: gitignored working state.
docker run --rm -v "${REPO_ROOT}":/src -w /src \
    "${SEMGREP_IMAGE}" \
    semgrep scan \
    --config=p/golang \
    --config=p/security-audit \
    --metrics=off \
    --error \
    --exclude=.local

echo
echo "==> clean: no Semgrep findings"
