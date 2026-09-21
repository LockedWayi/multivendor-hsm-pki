# shellcheck shell=bash
# Sourced: every name defined here is read by the script that sources it.
# shellcheck disable=SC2034
# Pinned third-party references, in one place. Sourced, never executed:
#
#   . "$(dirname "$0")/scanner-pins.sh"
#
# Images are pinned by digest. A tag is a pointer its publisher can move.
# The tag beside each digest is for the reader; Docker resolves the digest.
#
# Nothing here decides what a verifier trusts. The trust-anchor inputs are
# supplied from outside the tree; see ci/fetch-trust-anchor.sh.

# aquasec/trivy:0.74.0
TRIVY_IMAGE="aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"

# semgrep/semgrep:1.177.0
SEMGREP_IMAGE="semgrep/semgrep@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198"

# zricethezav/gitleaks:v8.30.1
GITLEAKS_IMAGE="zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

# ghcr.io/opentofu/opentofu:1.12.6. Must stay >= the required_version in
# deploy/terraform/environments/*/versions.tf, which needs 1.10.0's native
# S3 conditional-write locking.
TOFU_IMAGE="ghcr.io/opentofu/opentofu@sha256:22cb52f6c5bf5c72a48a8f56d993d8df3e9462b1cdfb5db7e77143c87e8d159f"

# alpine:3. Used for one root-owned file operation at a time: chown a
# signature bundle, delete token state a root container created.
ALPINE_IMAGE="alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
TOFU_CLEANUP_IMAGE="$ALPINE_IMAGE"

# koalaman/shellcheck:v0.11.0
# ci/lint-shell.sh runs this image locally and in the pipeline, so the two
# verdicts are one claim whatever shellcheck the host has installed. The
# first line of this comment is read by ci/check-pin-freshness: image and
# tag, nothing after them.
SHELLCHECK_IMAGE="koalaman/shellcheck@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d"

# registry:2. The throwaway registry ci/signing-mechanism-test.sh pushes
# into. It lives for one run and is removed with it.
REGISTRY_IMAGE="registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"

# golang.org/x/vuln/cmd/govulncheck. A module version rather than an image:
# the module proxy's checksum database makes a released version immutable.
GOVULNCHECK_VERSION="v1.8.0"

# requireSuppressionReporting refuses a trivy invocation that reads the
# shared allowlist without also reporting what it suppressed.
#
#   requireSuppressionReporting "${args[@]}"
#
# Why this is a guard and not a comment. ci/vuln-gate learns which
# allowlist entries trivy used by reading --show-suppressed output, and
# that is how an entry which has stopped matching anything is caught. But
# a trivy report from a run that suppressed nothing is indistinguishable
# from one that was never asked -- both simply omit the field, and the
# report's metadata records no flags. Measured on 0.74.0, not assumed.
#
# So the mistake cannot be detected downstream. It can only be prevented
# here, where somebody edits the command.
requireSuppressionReporting() {
    local has_ignorefile=0 has_show=0 arg
    for arg in "$@"; do
        case "$arg" in
            --ignorefile|--ignorefile=*) has_ignorefile=1 ;;
            --show-suppressed) has_show=1 ;;
        esac
    done
    if [ "$has_ignorefile" = "1" ] && [ "$has_show" = "0" ]; then
        echo "scanner-pins: this trivy run reads the allowlist with --ignorefile but not --show-suppressed." >&2
        echo "scanner-pins: without it the report cannot say which entries were used, and every entry would" >&2
        echo "scanner-pins: read as unused. Add --show-suppressed, or stop passing --ignorefile." >&2
        return 1
    fi
    return 0
}

# buildGoImage prints the builder image the shipped binary is compiled
# with, read from the service Dockerfile. govulncheck and the Go verifiers
# run in that image so they see the standard library the binary ships with.
buildGoImage() {
    local dockerfile="$1" matches
    matches="$(grep -cE '^FROM golang:[^ ]+@sha256:[0-9a-f]{64} AS build$' "$dockerfile" || true)"
    if [ "$matches" != "1" ]; then
        echo "scanner-pins: expected exactly one digest-pinned 'AS build' stage in $dockerfile, found $matches" >&2
        return 1
    fi
    sed -nE 's/^FROM (golang:[^ ]+@sha256:[0-9a-f]{64}) AS build$/\1/p' "$dockerfile"
}

# goRun runs `go run <package> <args>` inside the builder image with the
# repository mounted at /repo. Paths in the arguments must be written as
# the container sees them, /repo/... . The Go build cache under
# .local/ci-cache is mounted when it exists.
goRun() {
    local repo_root image
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    image="$(buildGoImage "$repo_root/deploy/docker/Dockerfile")" || return 1
    local cache_args=()
    if [ -d "$repo_root/.local/ci-cache/gobuild" ]; then
        cache_args+=(-v "$repo_root/.local/ci-cache/gobuild":/root/.cache/go-build)
    fi
    if [ -d "$repo_root/.local/ci-cache/gomod" ]; then
        cache_args+=(-v "$repo_root/.local/ci-cache/gomod":/go/pkg/mod)
    fi
    docker run --rm "${cache_args[@]}" -v "$repo_root":/repo -w /repo -e GOFLAGS=-mod=readonly \
        "$image" sh -c 'git config --global --add safe.directory /repo >/dev/null && exec go run "$@"' sh "$@"
}
