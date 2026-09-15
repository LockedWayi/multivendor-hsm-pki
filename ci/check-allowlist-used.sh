#!/usr/bin/env bash
#
# Fail when an allowlist entry suppressed nothing.
#
#   ci/check-allowlist-used.sh <hits.json> [<hits.json> ...]
#
# An exception that has stopped matching is an allowance nobody reviews,
# and from the outside it is indistinguishable from a clean scan -- the
# failure ci/vuln-allowlist.yaml's own header describes and which, until
# this script, nothing enforced.
#
# Why it takes several files. No single scanner can decide that an entry
# is unused. `trivy fs` and `trivy image` read the allowlist natively
# through --ignorefile and suppress findings govulncheck never sees;
# govulncheck reaches call graphs trivy does not. An entry that covers a
# trivy-only finding matches nothing in govulncheck and is still correct.
# So each scanner records what it used and the union is judged here, once.
#
# The hits files are produced by ci/scan-deps.sh (govulncheck and
# trivy fs) and ci/scan-image.sh (trivy image). In CI they cross job
# boundaries as artifacts, because those two scans run in parallel jobs.
#
# Rejected alternative: a per-entry "scanners:" field in the allowlist, so
# each scanner could check its own entries with no union and no artifacts.
# trivy tolerates the unknown key -- measured on 0.74.0, it parses and
# suppresses correctly -- so it was feasible. It was rejected because the
# author of an entry would be *declaring* which scanner sees the finding
# rather than anything measuring it, and a wrong declaration would make
# the check pass by construction. A claim is not a measurement.
set -euo pipefail

[ "$#" -ge 1 ] || { echo "usage: ci/check-allowlist-used.sh <hits.json> [...]" >&2; exit 2; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"

args=()
for f in "$@"; do
    [ -f "$f" ] || { echo "check-allowlist-used: no hits file at $f" >&2; exit 1; }
    abs="$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"
    case "$abs" in
        "$REPO_ROOT"/*) ;;
        *) echo "check-allowlist-used: $f is outside $REPO_ROOT; the checker runs in a container that mounts only the repository" >&2; exit 1 ;;
    esac
    args+=(-require-used "/repo/${abs#"$REPO_ROOT/"}")
done

# Who must have reported. A union computed over two of the three scanners
# is not a union: an entry only the absent one uses reads as unused, and
# with an empty allowlist it reads as a clean pass instead -- the same
# defect in the other direction, where a scanner whose report never
# arrived is invisible. Naming them here means a missing artifact, a
# renamed hits file or a scanner that stopped writing one is a red run
# rather than a quieter verdict.
#
# Add a name when a scanner starts consuming ci/vuln-allowlist.yaml.
EXPECTED=(govulncheck trivy-fs trivy-image)
for scanner in "${EXPECTED[@]}"; do
    args+=(-expect-scanner "$scanner")
done

echo "==> allowlist entries against what the scanners actually suppressed"
goRun ./ci/vuln-gate -allowlist ci/vuln-allowlist.yaml "${args[@]}"
