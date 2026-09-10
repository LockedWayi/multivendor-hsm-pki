#!/usr/bin/env bash
# Static checks for the OpenTofu tree: formatting, validity,
# misconfiguration and secret scanning.
#
# trivy config, not tfsec: tfsec is deprecated and merged into Trivy.
#
# A clean trivy config run here is a narrow claim. Trivy ships no rules for
# Hostinger's hostinger_vps, so a zero-finding run shows the tool ran and
# had nothing to say about this provider. Trivy's secret scanner runs over
# the same tree; it pattern-matches file contents regardless of provider,
# and it caught a planted token once.
#
# fmt and validate are here because trivy config parses HCL, and a file it
# cannot parse produces no findings rather than an error.
#
#   ci/terraform-scan.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

TF_DIR="${REPO_ROOT}/deploy/terraform"

# Both tools run in pinned containers, not off the host's PATH.
tofu() {
    docker run --rm -v "${REPO_ROOT}":/repo -w /repo \
        -e TF_IN_AUTOMATION=1 \
        "${TOFU_IMAGE}" "$@"
}
trivy() {
    docker run --rm -v "${REPO_ROOT}":/repo -w /repo \
        -v "${REPO_ROOT}/.local/scan":/out \
        "${TRIVY_IMAGE}" --cache-dir /out/cache "$@"
}
mkdir -p "${REPO_ROOT}/.local/scan/cache"

echo "==> tofu fmt -check"
tofu fmt -check -recursive -diff /repo/deploy/terraform

# tofu init writes a root-owned .terraform/ directory into each root
# module. Cleaned up here.
cleanup_tofu_state() {
    docker run --rm -v "${REPO_ROOT}":/repo -w /repo "${TOFU_CLEANUP_IMAGE}" \
        sh -c 'rm -rf deploy/terraform/environments/*/.terraform' || true
}
trap cleanup_tofu_state EXIT

echo
echo "==> tofu validate, per root module"
# -backend=false: the backend is a MinIO bucket CI cannot reach, and
# validate needs the providers, not the state. Root modules only: validate
# on a root module also validates the child modules it calls. A module no
# environment references would go unvalidated; both use modules/compute.
validated=0
for dir in "${TF_DIR}"/environments/*/; do
    # compgen, not a test on a glob: the test form expands to several
    # words when a directory holds several .tf files and fails as a syntax
    # error. The first version of this loop skipped every directory.
    compgen -G "${dir}*.tf" >/dev/null || continue
    rel="${dir#"${REPO_ROOT}/"}"
    echo "    ${rel}"
    tofu -chdir="/repo/${rel}" init -backend=false -input=false -no-color >/dev/null
    tofu -chdir="/repo/${rel}" validate -no-color
    validated=$((validated + 1))
done

# A check that examined nothing must not report success.
if [ "${validated}" -eq 0 ]; then
    echo "terraform-scan: validated 0 directories under ${TF_DIR}; expected at least one" >&2
    exit 1
fi
echo "    ${validated} director$([ "${validated}" -eq 1 ] && echo y || echo ies) validated"

echo
echo "==> trivy config: HIGH and CRITICAL misconfigurations"
# No --no-progress here: `trivy config` does not accept it, unlike
# `trivy fs` and `trivy image`.
trivy config --exit-code 1 --severity HIGH,CRITICAL \
    --quiet --skip-version-check /repo/deploy/terraform

echo
echo "==> trivy: secrets in the OpenTofu tree"
trivy fs --scanners secret --exit-code 1 \
    --quiet --skip-version-check --no-progress /repo/deploy/terraform

echo
echo "==> clean: OpenTofu tree formatted, valid, and free of blocking findings"
