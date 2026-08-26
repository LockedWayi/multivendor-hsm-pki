#!/usr/bin/env bash
# Computes test coverage over CI-reachable code only, and fails if it is
# below the floor. "CI-reachable" excludes the files listed in
# coverage-exclude.txt — vendor adapters that need a proprietary SDK or HSM
# hardware this pipeline does not have (see that file's header, CLAUDE.md
# §2.3). Those adapters are validated separately, by the conformance suite
# passing against real hardware in the maintainer's own environment; a
# coverage percentage is not a meaningful gate for code CI cannot execute.
#
# Usage: ci/coverage.sh [go test flags...]
#   COVERAGE_THRESHOLD=70 ci/coverage.sh -race
set -euo pipefail

THRESHOLD="${COVERAGE_THRESHOLD:-70}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXCLUDE_FILE="${SCRIPT_DIR}/coverage-exclude.txt"

RAW_PROFILE="$(mktemp)"
FILTERED_PROFILE="$(mktemp)"
trap 'rm -f "$RAW_PROFILE" "$FILTERED_PROFILE"' EXIT

# atomic, not set: -race requires it, and it is a safe default for
# non-race runs too.
go test ./... -covermode=atomic -coverprofile="$RAW_PROFILE" "$@"

# The profile's first line is the "mode: set" header; every line after is
# "file:startLine.startCol,endLine.endCol numStatements count".
head -n1 "$RAW_PROFILE" >"$FILTERED_PROFILE"
EXCLUDE_PATTERNS="$(grep -v '^#' "$EXCLUDE_FILE" | grep -v '^[[:space:]]*$' || true)"
if [ -n "$EXCLUDE_PATTERNS" ]; then
	tail -n +2 "$RAW_PROFILE" | grep -v -F -f <(printf '%s\n' "$EXCLUDE_PATTERNS") >>"$FILTERED_PROFILE" || true
else
	tail -n +2 "$RAW_PROFILE" >>"$FILTERED_PROFILE"
fi

SUMMARY="$(go tool cover -func="$FILTERED_PROFILE")"
echo "$SUMMARY"
PCT="$(echo "$SUMMARY" | tail -1 | grep -oE '[0-9]+\.[0-9]+')"

if ! awk -v pct="$PCT" -v threshold="$THRESHOLD" 'BEGIN { exit !(pct >= threshold) }'; then
	echo "coverage ${PCT}% is below the ${THRESHOLD}% floor" \
		"(vendor-adapter files excluded per ci/coverage-exclude.txt)" >&2
	exit 1
fi
echo "coverage ${PCT}% meets the ${THRESHOLD}% floor" \
	"(vendor-adapter files excluded per ci/coverage-exclude.txt)"
