#!/usr/bin/env bash
#
# Scan the service image and produce its SBOM.
#
# The scan is a gate: it exits non-zero on any HIGH or CRITICAL finding.
# The SBOM is evidence: it says what is in the image, so "are we affected"
# can be answered about a CVE published after this build.
#
#   ci/scan-image.sh                          # scans hsm-pki-server:local
#   ci/scan-image.sh myrepo/hsm-pki:v1.2.3    # or any image reference
#
# Findings land in .local/scan/ (gitignored). The image must exist locally.
set -euo pipefail

IMAGE="${1:-hsm-pki-server:local}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT="${HSM_PKI_SCAN_OUT:-$REPO_ROOT/.local/scan}"
# The scanner pin is shared with ci/scan-deps.sh.
. "${SCRIPT_DIR}/scanner-pins.sh"

# Accepted findings come from the one reviewed allowlist the dependency
# scan uses (ci/vuln-allowlist.yaml).
ALLOWLIST="$REPO_ROOT/ci/vuln-allowlist.yaml"

mkdir -p "$OUT" "$OUT/cache"

# ci/vuln-gate runs in the builder container, which mounts the repository
# and nothing else, so it can only read a report written inside the tree.
case "$OUT" in
    "$REPO_ROOT"/*) OUT_REL="${OUT#"$REPO_ROOT/"}" ;;
    *) echo "scan-image: HSM_PKI_SCAN_OUT must be inside $REPO_ROOT; got $OUT" >&2; exit 1 ;;
esac

trivy() {
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$OUT":/out \
        -v "$ALLOWLIST":/vuln-allowlist.yaml:ro \
        "$TRIVY_IMAGE" --cache-dir /out/cache "$@"
}

echo "==> scanning $IMAGE for HIGH and CRITICAL vulnerabilities"
# --exit-code 1 makes this a gate. --ignore-unfixed is not set: a
# vulnerability with no fix is still a vulnerability, and hiding it means
# nobody decides to accept it.
set +e
trivy image --quiet --scanners vuln --severity HIGH,CRITICAL \
    --ignorefile /vuln-allowlist.yaml --exit-code 1 "$IMAGE"
scan_status=$?
set -e

echo
echo "==> writing the SBOM"
# CycloneDX, because it is what cosign attests and verifies natively.
trivy image --quiet --format cyclonedx --output /out/sbom.cdx.json "$IMAGE"

echo
echo "==> recording which allowlist entries trivy image used"
# A second invocation rather than one JSON run: the gate above keeps its
# exit status and its table exactly as they were, and this pass only
# collects. The database is already in $OUT/cache.
#
# --exit-code is deliberately absent. A finding is the gate's verdict, not
# this pass's; deciding it twice would let two places disagree about one
# scan.
TRIVY_IMAGE_REPORT_ARGS=(
    image --quiet --scanners vuln --severity "HIGH,CRITICAL"
    --ignorefile /vuln-allowlist.yaml --show-suppressed
    --format json --output /out/trivy-image.json "$IMAGE"
)
requireSuppressionReporting "${TRIVY_IMAGE_REPORT_ARGS[@]}"
trivy "${TRIVY_IMAGE_REPORT_ARGS[@]}"
goRun ./ci/vuln-gate -allowlist "ci/vuln-allowlist.yaml" \
    -trivy "/repo/$OUT_REL/trivy-image.json" \
    -write-hits "/repo/$OUT_REL/hits-trivy-image.json" -scanner trivy-image

components=$(python3 -c "
import json
print(len(json.load(open('$OUT/sbom.cdx.json')).get('components', [])))
" 2>/dev/null || echo '?')

echo "    $OUT/sbom.cdx.json ($components components)"
echo
if [ "$scan_status" -ne 0 ]; then
    echo "==> FAILED: unresolved HIGH or CRITICAL findings above."
    echo "    Fix them, or record each one with a reason and an expiry date"
    echo "    in ci/vuln-allowlist.yaml. Do not silence this script."
    exit "$scan_status"
fi
echo "==> clean: no HIGH or CRITICAL vulnerabilities"
