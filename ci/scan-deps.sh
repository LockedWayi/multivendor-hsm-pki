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
GOVULN_LOG="${OUT}/govulncheck-stage.log"
# The last line ci/govulncheck-in-builder.sh prints when it has run the
# whole scan. Its absence is what this script checks; keep the two in step.
GOVULN_MARKER="govulncheck-in-builder: complete"
# One hits file per scanner. ci/vuln-gate judges the union of them, because
# an entry may legitimately cover a finding only one scanner can see.
HITS_GOVULN="hits-govulncheck.json"
HITS_TRIVY_FS="hits-trivy-fs.json"
mkdir -p "${OUT}/cache"

# ci/vuln-gate runs in the builder container, which mounts the repository
# and nothing else, so it can only read a report written inside the tree.
# Said out loud rather than left as a path that would quietly resolve
# wrong: HSM_PKI_SCAN_OUT pointing outside the repository is a
# configuration this script cannot serve.
case "${OUT}" in
    "${REPO_ROOT}"/*) OUT_REL="${OUT#"${REPO_ROOT}/"}" ;;
    *) echo "scan-deps: HSM_PKI_SCAN_OUT must be inside ${REPO_ROOT}; got ${OUT}" >&2; exit 1 ;;
esac

GO_IMAGE="$(buildGoImage "${REPO_ROOT}/deploy/docker/Dockerfile")"

echo "==> govulncheck ${GOVULNCHECK_VERSION} on ${GO_IMAGE}"
echo "    (the builder image the shipped binary is compiled with, so the"
echo "     standard-library half of the answer is about the right toolchain)"
# The stage itself lives in ci/govulncheck-in-builder.sh rather than in an
# inline `sh -c "..."` here. The inline form was a multi-line double-quoted
# bash string, and a bare `"` in one of its comments closed that string
# early: sh received a script that stopped three lines after `go install`,
# ran none of the scan, and exited 0. See that file's header.
docker run --rm \
    -v "${REPO_ROOT}":/repo -w /repo \
    -e GOFLAGS=-mod=readonly \
    -v "${OUT}":/out \
    -e GOVULNCHECK_VERSION="${GOVULNCHECK_VERSION}" \
    -e ALLOWLIST="${ALLOWLIST}" \
    -e HITS_OUT="/out/${HITS_GOVULN}" \
    "${GO_IMAGE}" sh /repo/ci/govulncheck-in-builder.sh 2>&1 | tee "${GOVULN_LOG}"

# Exit status cannot tell a clean scan from a scan that never happened:
# both are 0. So the pass condition is evidence of work in the log, not the
# zero -- the stage prints the marker below as its last line, and anything
# that ends it early fails here instead of reporting clean.
if ! grep -qF "${GOVULN_MARKER}" "${GOVULN_LOG}"; then
    echo "scan-deps: the govulncheck stage did not run to completion." >&2
    echo "scan-deps: no '${GOVULN_MARKER}' in ${GOVULN_LOG}; treat this as a failed scan, not a clean one." >&2
    exit 1
fi

echo
echo "==> trivy fs: HIGH and CRITICAL in the module graph"
# .local/ holds trivy's own database; scanning it means scanning the
# scanner.
TRIVY_FS_ARGS=(
    fs --scanners vuln --severity "HIGH,CRITICAL" --exit-code 1
    --ignorefile "/repo/${ALLOWLIST}" --skip-dirs .local
    --quiet --skip-version-check --no-progress /repo
)
docker run --rm \
    -v "${REPO_ROOT}":/repo -v "${OUT}":/out -w /repo \
    "${TRIVY_IMAGE}" --cache-dir /out/cache "${TRIVY_FS_ARGS[@]}"

echo
echo "==> recording which allowlist entries trivy fs used"
# A second invocation rather than one JSON run, deliberately: the gate
# above keeps its exit status and its human-readable table exactly as they
# were, and this pass only collects. The database is already in
# ${OUT}/cache, so it re-reads rather than re-fetches.
#
# The gate's arguments are reused with --exit-code dropped: a finding is
# the gate's verdict, not this pass's, and re-deciding it here would mean
# two places could disagree about the same scan.
TRIVY_FS_REPORT_ARGS=()
for arg in "${TRIVY_FS_ARGS[@]}"; do
    [ "$arg" = "--exit-code" ] && continue
    [ "$arg" = "1" ] && continue
    TRIVY_FS_REPORT_ARGS+=("$arg")
done
TRIVY_FS_REPORT_ARGS+=(--show-suppressed --format json --output "/out/trivy-fs.json")
requireSuppressionReporting "${TRIVY_FS_REPORT_ARGS[@]}"
docker run --rm \
    -v "${REPO_ROOT}":/repo -v "${OUT}":/out -w /repo \
    "${TRIVY_IMAGE}" --cache-dir /out/cache "${TRIVY_FS_REPORT_ARGS[@]}"
goRun ./ci/vuln-gate -allowlist "${ALLOWLIST}" \
    -trivy "/repo/${OUT_REL}/trivy-fs.json" \
    -write-hits "/repo/${OUT_REL}/${HITS_TRIVY_FS}" -scanner trivy-fs

echo
echo "==> clean: no blocking dependency vulnerabilities"
echo "    allowlist hits: ${OUT}/${HITS_GOVULN}, ${OUT}/${HITS_TRIVY_FS}"
