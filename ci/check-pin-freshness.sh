#!/usr/bin/env bash
#
# Report pinned third-party references that have fallen behind upstream.
#
#   ci/check-pin-freshness.sh                # exit 1 when a pin is behind
#   ci/check-pin-freshness.sh -report-only   # print the same report, exit 0
#
# The pins in ci/scanner-pins.sh are invisible to Dependabot: its docker
# ecosystem reads Dockerfile FROM lines and its github-actions ecosystem
# reads uses: values, and a digest held anywhere else is read by neither.
# Those pins rot silently -- nothing breaks, they just stop receiving the
# fixes a tag would have brought.
#
# This is not a pull-request gate and must not become one. Upstream
# shipping a release is not a reason to fail somebody's unrelated change.
# It runs on a schedule; see .github/workflows/pin-freshness.yml.
#
# It reaches the network, which is why it is not in the suite gate: a gate
# whose verdict depends on a third party's uptime fails for reasons that
# have nothing to do with the change under review.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"
cd "$REPO_ROOT"

echo "==> pinned references, against upstream"
# Run in the same digest-pinned builder image everything else Go uses, so
# this needs no Go on the host.
goRun ./ci/check-pin-freshness -pins /repo/ci/scanner-pins.sh "$@"
