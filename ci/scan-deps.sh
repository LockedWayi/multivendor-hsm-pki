#!/usr/bin/env bash
#
# Dependency vulnerability scanning: two questions, asked separately.
#
#   trivy fs      is a vulnerable version present at all? Reads the module
#                 graph, blocks on any HIGH or CRITICAL.
#   govulncheck   does this code reach the vulnerable function? Builds the
#                 call graph, blocks only on a reachable one.
#
# trivy's answer is what an auditor reads off go.mod and what a downstream
# consumer inherits. govulncheck's answer says whether the vulnerability is
# exploitable here today. Exceptions to either come from one reviewed file,
# ci/vuln-allowlist.yaml. trivy reads it natively; ci/vuln-gate applies it
# to govulncheck and validates it for both.
#
#   ci/scan-deps.sh
#
# Needs docker and network: the vulnerability databases are fetched at scan
# time.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

OUT="${HSM_PKI_SCAN_OUT:-${REPO_ROOT}/.local/scan}"
ALLOWLIST="ci/vuln-allowlist.yaml"
mkdir -p "${OUT}/cache"

GO_IMAGE="$(buildGoImage "${REPO_ROOT}/deploy/docker/Dockerfile")"

echo "==> govulncheck ${GOVULNCHECK_VERSION} on ${GO_IMAGE}"
echo "    (the builder image the shipped binary is compiled with, so the"
echo "     standard-library half of the answer is about the right toolchain)"
# govulncheck writes JSON and ci/vuln-gate turns it into an exit status,
# because govulncheck -format json exits 0 even on a called vulnerability.
# safe.directory: the checkout is owned by the invoking user and the
# container runs as root.
docker run --rm \
    -v "${REPO_ROOT}":/repo -w /repo \
    -e GOFLAGS=-mod=readonly \
    "${GO_IMAGE}" sh -c "
        set -e
        git config --global --add safe.directory /repo

        # Retry the steps that reach the network, and only those. A module
        # proxy reset is not a finding. The scan itself is not retried.
        retry() {
            attempt=1
            while true; do
                if \"\$@\"; then return 0; fi
                if [ \"\$attempt\" -ge 3 ]; then
                    echo \"scan-deps: '\$*' failed after \$attempt attempts\" >&2
                    return 1
                fi
                echo \"scan-deps: '\$*' failed, retrying (\$attempt/3)\" >&2
                sleep \$((attempt * 5))
                attempt=\$((attempt + 1))
            done
        }

        retry go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}

        # The module cache is filled first, where a proxy failure is
        # retried; inside govulncheck's loader it reads as a broken
        # dependency. Plain "go mod download", not "all": the "all" pattern
        # writes the checksums of test dependencies of dependencies into
        # go.sum and leaves the checkout dirty.
        retry go mod download

        # -format json, because text cannot be filtered against the
        # allowlist. Test files are out of scope: the question is what the
        # shipped binary reaches.
        \"\$(go env GOPATH)\"/bin/govulncheck -format json ./... > /tmp/govulncheck.json
        go run ./ci/vuln-gate -govulncheck /tmp/govulncheck.json -allowlist ${ALLOWLIST}
    "

echo
echo "==> trivy fs: HIGH and CRITICAL in the module graph"
# .local/ holds trivy's own database; scanning it means scanning the
# scanner.
docker run --rm \
    -v "${REPO_ROOT}":/repo -v "${OUT}":/out -w /repo \
    "${TRIVY_IMAGE}" --cache-dir /out/cache \
    fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
    --ignorefile "/repo/${ALLOWLIST}" --skip-dirs .local \
    --quiet --skip-version-check --no-progress /repo

echo
echo "==> clean: no blocking dependency vulnerabilities"
