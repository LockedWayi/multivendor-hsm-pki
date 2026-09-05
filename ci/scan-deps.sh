#!/usr/bin/env bash
#
# Dependency vulnerability scanning: the two questions, asked separately.
#
#   trivy fs      "is a vulnerable version present at all?"  -- reads the
#                 module graph, blocks on any HIGH or CRITICAL.
#   govulncheck   "does this code actually reach the vulnerable function?"
#                 -- builds the call graph, blocks only on a reachable one.
#
# Both are wanted and they are not redundant. trivy's answer is what an
# auditor reads off go.mod and what a downstream consumer inherits; it is
# also the only one available for a dependency whose vulnerable code is
# reached through reflection or a build tag. govulncheck's answer is the
# one that says whether the vulnerability is exploitable *here* today, and
# it is the difference between an upgrade that is urgent and one that is
# housekeeping. A pipeline with only the first cries wolf; a pipeline with
# only the second ships a library it never calls until the day somebody
# calls it.
#
# Exceptions to either come from one reviewed file, ci/vuln-allowlist.yaml.
# trivy reads it natively; ci/vuln-gate applies it to govulncheck and
# validates it for both (see that program's doc comment for why the
# validation cannot be left to trivy).
#
# Run it locally exactly as CI does:
#
#   ci/scan-deps.sh
#
# Needs docker and network: the vulnerability databases are fetched at scan
# time, which is the point -- a scanner pinned to a database is a scanner
# that stops finding new things.
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
# Everything runs in one container invocation: govulncheck writes JSON, and
# ci/vuln-gate -- a Go program in this repository -- turns it into an exit
# status. It has to, because `govulncheck -format json` exits 0 even when it
# finds a called vulnerability (measured; see ci/vuln-gate/main.go).
#
# safe.directory: the checkout is owned by the invoking user and this
# container runs as root, so git otherwise refuses to read the repository
# and go reports it as a VCS error rather than a permission one.
docker run --rm \
    -v "${REPO_ROOT}":/repo -w /repo \
    -e GOFLAGS=-mod=readonly \
    "${GO_IMAGE}" sh -c "
        set -e
        git config --global --add safe.directory /repo

        # Retry the steps that reach the network, and only those. A module
        # proxy reset is not a finding: on 2026-09-05 one turned main red
        # with 'read: connection reset by peer' while fetching
        # modernc.org/sqlite, on a tree whose pull-request run had been
        # green ninety seconds earlier. A pipeline that reports the network
        # as a vulnerability teaches its readers to re-run red checks, and
        # that is the habit which later waves a real finding through.
        #
        # The scan itself is deliberately NOT retried. Retrying an answer
        # until it changes is how a gate becomes a suggestion.
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

        # Pre-populate the module cache before the analysis starts, so a
        # transient proxy failure surfaces here -- where it is retried --
        # instead of inside govulncheck's package loader, which has no
        # retry and reports it as 'could not import ... (invalid package
        # name)': a message that reads like a broken dependency rather
        # than a broken connection, and cost an hour on 2026-09-05.
        #
        # 'go mod download', not 'go mod download all'. The 'all' pattern
        # reaches the test dependencies of dependencies, which this scan
        # never loads, and writes their checksums into go.sum -- measured,
        # thirty lines -- so the gate would leave the checkout dirty and
        # the diff would invite somebody to commit them.
        retry go mod download

        # -format json rather than text because text cannot be filtered
        # against the allowlist. Test files are deliberately out of scope:
        # the question is what the shipped binary can reach.
        \"\$(go env GOPATH)\"/bin/govulncheck -format json ./... > /tmp/govulncheck.json
        go run ./ci/vuln-gate -govulncheck /tmp/govulncheck.json -allowlist ${ALLOWLIST}
    "

echo
echo "==> trivy fs: HIGH and CRITICAL in the module graph"
# .local/ is gitignored working state and holds trivy's own vulnerability
# database; scanning it means scanning the scanner.
docker run --rm \
    -v "${REPO_ROOT}":/repo -v "${OUT}":/out -w /repo \
    "${TRIVY_IMAGE}" --cache-dir /out/cache \
    fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
    --ignorefile "/repo/${ALLOWLIST}" --skip-dirs .local \
    --quiet --skip-version-check --no-progress /repo

echo
echo "==> clean: no blocking dependency vulnerabilities"
