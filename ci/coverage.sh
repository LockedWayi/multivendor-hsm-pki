#!/usr/bin/env bash
# Computes test coverage over CI-reachable code only, and fails if it is
# below the floor. "CI-reachable" excludes the files listed in
# coverage-exclude.txt — vendor adapters that need a proprietary SDK or HSM
# hardware this pipeline does not have (see that file's header, the engineering contract
# the verified-claim split). Those adapters are validated separately, by the conformance suite
# passing against real hardware in the maintainer's own environment; a
# coverage percentage is not a meaningful gate for code CI cannot execute.
#
# Usage: ci/coverage.sh [go test flags...]
#   COVERAGE_THRESHOLD=70 ci/coverage.sh -race
#   COVERAGE_BADGE=docs/coverage.svg ci/coverage.sh -race        # write the badge
#   COVERAGE_BADGE=docs/coverage.svg COVERAGE_BADGE_CHECK=1 ...  # verify it
#
# # The badge is a committed file that CI verifies, not one CI publishes
#
# The obvious ways to keep a coverage badge current both cost something this
# repository should not pay. Committing the badge from a workflow needs
# `contents: write` on a job that pushes to the default branch -- a write
# credential added to a pipeline whose entire subject is supply-chain
# provenance. Publishing to a gist or a third-party service needs a token
# secret and puts the number somewhere the repository cannot verify.
#
# So the badge is checked in like a lockfile, and CI recomputes it and fails
# on a mismatch (COVERAGE_BADGE_CHECK=1). The pipeline needs no new
# permission and no new secret, and the badge cannot silently go stale: a
# number that stops being true turns the build red.
#
# It shows the measured percentage rounded DOWN to a whole number. Down,
# because a coverage badge that rounds up overstates, and by whole numbers
# so the file changes when the figure meaningfully does rather than on every
# commit that moves it a tenth.
#
# Run it where SoftHSM2 is, which on a developer machine means inside the
# ci/softhsm2-dev.Dockerfile image and not on the host. A host without
# SOFTHSM2_MODULE set skips every token-touching test by design (the engineering contract
# the every-backend rule: a missing backend skips, never fails), so the suite stays green
# while the coverage it produces collapses — measured 34.2% on such a host
# against 79.1% in the container. The gate then fails for a reason that has
# nothing to do with the code being measured, which is the worst kind of
# red.
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
# Written by hand rather than fetched from a badge service: an image loaded
# from a third party on every view of the README is a request this
# repository does not need to make, and one more thing that can change
# under it.
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
	# install rather than cp: mktemp makes the source 0600, and a file
	# that is about to be committed should be readable. The chown matters
	# for the same reason: this script is normally run inside the dev
	# container, which is root, so without it the badge lands root-owned
	# inside a user-owned checkout and the next `git add` fails for a
	# reason that looks nothing like its cause.
	install -m 0644 "$BADGE_TMP" "$COVERAGE_BADGE"
	chown --reference="$(dirname "$COVERAGE_BADGE")" "$COVERAGE_BADGE" 2>/dev/null || true
	echo "coverage badge written to ${COVERAGE_BADGE} (${BADGE_PCT}%)"
fi
