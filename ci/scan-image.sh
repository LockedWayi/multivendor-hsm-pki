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
