#!/usr/bin/env bash
#
# SAST: Semgrep over this repository's own Go code.
#
# The third question in the set, and the one nothing else asks. The secret
# scan reads what was accidentally committed; the dependency scan reads what
# was imported; this reads what was *written* here. A defect this finds was
# never in anybody's dependency graph and never in a CVE feed -- it is ours,
# and it exists because somebody wrote it.
#
# Rulesets: p/golang and p/security-audit. Deliberately not p/secrets --
# gitleaks already owns that question in ci.yml and owns it better, over the
# full history rather than the working tree, so adding it here would produce
# a second opinion about the same files with no more coverage.
#
# --error is what makes this a gate rather than a report: without it semgrep
# prints findings and exits 0 (CLAUDE.md §3.4).
#
# Exceptions are per-rule and per-line `nosemgrep` comments in the source
# itself, each with the reason beside it. Never a disabled ruleset, and
# never a path exclusion: the narrowest form is the one that keeps working.
# A path exclusion would exempt every future finding in that file too --
# including the one nobody has written yet -- and this repository's two
# exempted files are `internal/ca/ca.go` and `internal/pkcs11/secure_pin.go`,
# which are precisely the two files where a real finding would matter most.
#
# Usage: ci/scan-code.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

# --metrics=off: this is a private repository and its file names are not
# telemetry anyone else needs.
# --exclude=.local: gitignored working state, including other scanners'
# databases.
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
