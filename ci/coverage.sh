#!/usr/bin/env bash
# Computes test coverage over CI-reachable code and fails below the floor.
# The files in coverage-exclude.txt are vendor adapters that need a
# proprietary SDK this pipeline does not have. Those are checked by the
# conformance suite against ProtectToolkit-C software emulation in the
# maintainer's own environment.
#
#   COVERAGE_THRESHOLD=70 ci/coverage.sh -race
#   COVERAGE_BADGE=docs/coverage.svg ci/coverage.sh -race        # write the badge
#   COVERAGE_BADGE=docs/coverage.svg COVERAGE_BADGE_CHECK=1 ...  # verify it
#
# The badge is committed like a lockfile and CI recomputes it. Committing
# it from a workflow would need contents: write on the default branch. The
# figure rounds down to a whole number.
#
# Run it inside ci/softhsm2-dev.Dockerfile. A host without the SoftHSM2
# module skips every token-touching test, and the coverage collapses
# (34.2% on such a host against 79.1% in the container, same commit).
set -euo pipefail

THRESHOLD="${COVERAGE_THRESHOLD:-70}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXCLUDE_FILE="${SCRIPT_DIR}/coverage-exclude.txt"

RAW_PROFILE="$(mktemp)"
FILTERED_PROFILE="$(mktemp)"
trap 'rm -f "$RAW_PROFILE" "$FILTERED_PROFILE"' EXIT

# atomic: -race requires it.
#
# -count=1: CI restores Go's build cache between runs, and that cache
# carries the test *result* cache with it. Go's content addressing makes
# replaying a previous verdict sound for pure computation and unsound here:
# these tests drive a real SoftHSM2 token, and token state is not an input
# Go can hash. A cached pass means the token was never touched, which is the
# one thing this job exists to prove. It defeats the result cache only; the
# compilation cache, which is what makes this job slow (cgo, sqlite, race
# instrumentation), is untouched.
go test ./... -covermode=atomic -coverprofile="$RAW_PROFILE" -count=1 "$@"

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

if [ -z "${COVERAGE_BADGE:-}" ]; then
	exit 0
fi

# Floor to a whole number: never overstate.
BADGE_PCT="${PCT%.*}"
if [ "$BADGE_PCT" -ge 90 ]; then
	BADGE_COLOUR="#4c1"
elif [ "$BADGE_PCT" -ge 75 ]; then
	BADGE_COLOUR="#97ca00"
elif [ "$BADGE_PCT" -ge "$THRESHOLD" ]; then
	BADGE_COLOUR="#dfb317"
else
	BADGE_COLOUR="#e05d44"
fi

BADGE_TMP="$(mktemp)"
trap 'rm -f "$RAW_PROFILE" "$FILTERED_PROFILE" "$BADGE_TMP"' EXIT
# Written by hand, so the README makes no request to a third party.
cat >"$BADGE_TMP" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="104" height="20" role="img" aria-label="coverage: ${BADGE_PCT}%">
  <title>coverage: ${BADGE_PCT}%</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="104" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="61" height="20" fill="#555"/>
    <rect x="61" width="43" height="20" fill="${BADGE_COLOUR}"/>
    <rect width="104" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">
    <text x="315" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="510">coverage</text>
    <text x="315" y="140" transform="scale(.1)" textLength="510">coverage</text>
    <text x="815" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="330">${BADGE_PCT}%</text>
    <text x="815" y="140" transform="scale(.1)" textLength="330">${BADGE_PCT}%</text>
  </g>
</svg>
SVG

if [ "${COVERAGE_BADGE_CHECK:-0}" = "1" ]; then
	if ! cmp -s "$BADGE_TMP" "$COVERAGE_BADGE"; then
		echo "coverage badge ${COVERAGE_BADGE} is stale: it does not match the measured ${PCT}% (badge would read ${BADGE_PCT}%)." >&2
		echo "Regenerate it with COVERAGE_BADGE=${COVERAGE_BADGE} ci/coverage.sh -race -p 1 and commit the result." >&2
		exit 1
	fi
	echo "coverage badge ${COVERAGE_BADGE} is current (${BADGE_PCT}%)"
else
	# install, not cp: mktemp makes the source 0600. The chown matters
	# because this normally runs in the dev container as root.
	install -m 0644 "$BADGE_TMP" "$COVERAGE_BADGE"
	chown --reference="$(dirname "$COVERAGE_BADGE")" "$COVERAGE_BADGE" 2>/dev/null || true
	echo "coverage badge written to ${COVERAGE_BADGE} (${BADGE_PCT}%)"
fi
