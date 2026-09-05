#!/usr/bin/env bash
#
# Scan the service image and produce its SBOM.
#
# Two outputs with different jobs. The scan is a gate: it exits non-zero on
# any HIGH or CRITICAL finding, so a pipeline that ignores its exit status is
# the only way to ship a known-vulnerable image (CLAUDE.md §3.4, fail
# closed). The SBOM is evidence: it says what is in the image at all, which
# is what lets somebody answer "are we affected" about a CVE published after
# this build, without still having the image.
#
# Run it locally exactly as CI will (Phase 5.4):
#
#   ci/scan-image.sh                          # scans hsm-pki-server:local
#   ci/scan-image.sh myrepo/hsm-pki:v1.2.3    # or any image reference
#
# Findings land in .local/scan/ (gitignored). The scan needs the image to
# exist locally; build it first with deploy/docker/Dockerfile.
set -euo pipefail

IMAGE="${1:-hsm-pki-server:local}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT="${HSM_PKI_SCAN_OUT:-$REPO_ROOT/.local/scan}"
# The scanner pin moved to ci/scanner-pins.sh when ci/scan-deps.sh started
# needing the same one (Phase 5.3). It also became a digest rather than the
# 0.67.0 tag: a tag is a pointer its publisher can move, so a tag-pinned
# scanner still changes under you -- the same reasoning ci.yml already
# applies to its actions and to the gitleaks image (CLAUDE.md §3.8).
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

# Accepted findings come from the one reviewed allowlist the dependency
# scan uses, not a second file: an exception granted for a Go module is the
# same decision whether the scanner met it in go.mod or in the image built
# from it (ci/vuln-allowlist.yaml).
ALLOWLIST="$REPO_ROOT/ci/vuln-allowlist.yaml"

mkdir -p "$OUT" "$OUT/cache"

trivy() {
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$OUT":/out \
        -v "$ALLOWLIST":/vuln-allowlist.yaml:ro \
        "$TRIVY_IMAGE" --cache-dir /out/cache "$@"
}

echo "==> scanning $IMAGE for HIGH and CRITICAL vulnerabilities"
# --exit-code 1 is what makes this a gate rather than a report. --ignore-
# unfixed is deliberately NOT set: a vulnerability with no fix available is
# still a vulnerability, and hiding it means the decision to accept it is
# never made by anyone.
set +e
trivy image --quiet --scanners vuln --severity HIGH,CRITICAL \
    --ignorefile /vuln-allowlist.yaml --exit-code 1 "$IMAGE"
scan_status=$?
set -e

echo
echo "==> writing the SBOM"
# CycloneDX rather than SPDX, for one practical reason: it is what cosign
# attaches and verifies natively, and Phase 4.10 signs this image. An SBOM
# nobody can tie to the artifact it describes is a text file.
trivy image --quiet --format cyclonedx --output /out/sbom.cdx.json "$IMAGE"

components=$(python3 -c "
import json
print(len(json.load(open('$OUT/sbom.cdx.json')).get('components', [])))
" 2>/dev/null || echo '?')

echo "    $OUT/sbom.cdx.json ($components components)"
echo
if [ "$scan_status" -ne 0 ]; then
    echo "==> FAILED: unresolved HIGH or CRITICAL findings above."
    echo "    Fix them, or record each one with a reason and a re-check date"
    echo "    in docs/phases/phase-4-container-k8s.md (4.6). Do not silence"
    echo "    this script."
    exit "$scan_status"
fi
echo "==> clean: no HIGH or CRITICAL vulnerabilities"
