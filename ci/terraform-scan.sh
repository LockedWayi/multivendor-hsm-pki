#!/usr/bin/env bash
# Static checks for the OpenTofu tree: formatting, validity, and
# misconfiguration/secret scanning.
#
# trivy, not tfsec: tfsec is deprecated and merged into Trivy (Aqua
# Security), so `trivy config` is the maintained tool the phase file's
# "tfsec (or trivy config)" choice resolves to.
#
# A clean `trivy config` run here is a narrower claim than it looks for this
# repo: Hostinger's `hostinger_vps` is not a resource type Trivy ships
# rules for (confirmed empirically, not assumed -- see
# docs/phases/phase-3-infrastructure.md, sub-task 3.5), so a zero-finding
# run proves the tool executed and found nothing to say about *this*
# provider, not that the configuration is free of every possible
# misconfiguration class.
#
# Because those cloud-misconfiguration rules have zero coverage for this
# provider, the script also runs Trivy's secret scanner over the same tree.
# That check *is* reachable regardless of provider: it pattern-matches file
# contents for real-looking credentials, independent of any resource
# schema. It is what caught the deliberate demonstration mistake in
# sub-task 3.6 -- a hardcoded-looking token left in a variable's `default`.
#
# `fmt` and `validate` are not security checks and are here anyway. They are
# what makes the security checks worth reading: `trivy config` parses HCL,
# and a file it cannot parse produces no findings rather than an error, so
# an invalid configuration is indistinguishable from a clean one unless
# something else has already established that it parses.
#
# Usage: ci/terraform-scan.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

TF_DIR="${REPO_ROOT}/deploy/terraform"

# Both tools run in pinned containers rather than off the host's PATH. The
# previous version of this script called whatever `trivy` and `tofu` the
# developer happened to have installed, which made "it passed locally" a
# statement about that machine (CLAUDE.md §3.8).
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

# tofu init writes a .terraform/ directory into each root module it
# touches, as root, because the container is root. Left behind on a
# developer's machine those are root-owned files inside a user-owned
# checkout -- gitignored, so invisible to git status, and removable only
# with the same privilege that made them. Cleaned up here rather than
# explained in a troubleshooting note later.
cleanup_tofu_state() {
    docker run --rm -v "${REPO_ROOT}":/repo -w /repo "${TOFU_CLEANUP_IMAGE}" \
        sh -c 'rm -rf deploy/terraform/environments/*/.terraform' || true
}
trap cleanup_tofu_state EXIT

echo
echo "==> tofu validate, per root module"
# -backend=false is required, not a shortcut: the backend is a self-hosted
# MinIO bucket that CI cannot reach and holds no credentials for. Skipping
# it installs the providers -- which is all `validate` needs -- without
# touching remote state. A validate that needed state would be a validate
# that could not run on a pull request from a fork.
# Root modules only. `validate` on a root module also validates the child
# modules it calls -- measured, not assumed: an undeclared variable
# introduced in modules/compute/main.tf failed `validate` in
# environments/dev, reported against the module's own file and line. So
# iterating modules/ separately would re-check the same code while making
# tofu write a .terraform.lock.hcl into a directory that should not carry
# one, since a module does not choose its own provider versions.
#
# The gap this leaves, stated rather than hidden: a module no environment
# references would go unvalidated. Both environments use modules/compute
# today.
validated=0
for dir in "${TF_DIR}"/environments/*/; do
    # compgen, not `[ -e "${dir}"*.tf ]`: that form expands to several
    # words when a directory holds several .tf files, which makes `test`
    # fail as a syntax error rather than as "no match". The first version
    # of this loop did exactly that and skipped every directory in
    # silence -- a validate step that validated nothing and said nothing.
    compgen -G "${dir}*.tf" >/dev/null || continue
    rel="${dir#"${REPO_ROOT}/"}"
    echo "    ${rel}"
    tofu -chdir="/repo/${rel}" init -backend=false -input=false -no-color >/dev/null
    tofu -chdir="/repo/${rel}" validate -no-color
    validated=$((validated + 1))
done

# Fail closed on an empty loop (CLAUDE.md §3.4). Whatever the cause -- a
# moved directory, a glob that stops matching, the quoting bug above -- a
# check that silently examined nothing must not report success, because
# nothing distinguishes it from a check that examined everything and
# approved.
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
