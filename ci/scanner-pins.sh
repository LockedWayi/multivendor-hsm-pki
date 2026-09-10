# Pinned third-party references, in one place. Sourced, never executed:
#
#   . "$(dirname "$0")/scanner-pins.sh"
#
# Images are pinned by digest. A tag is a pointer its publisher can move.
# The tag beside each digest is for the reader; Docker resolves the digest.
#
# Nothing here decides what a verifier trusts. The trust-anchor inputs are
# supplied from outside the tree; see ci/fetch-trust-anchor.sh.

# aquasec/trivy:0.67.0
TRIVY_IMAGE="aquasec/trivy@sha256:94711c60051c6cab848a292e3a67f62623fcee361b2bb661f43b17184f4afdac"

# semgrep/semgrep:1.175.1
SEMGREP_IMAGE="semgrep/semgrep@sha256:51c9f53a4fce0d55e9abd08d7b96968654248a4b1122e77f20e0a49c0072446c"

# zricethezav/gitleaks:v8.30.1
GITLEAKS_IMAGE="zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"

# ghcr.io/opentofu/opentofu:1.12.6. Must stay >= the required_version in
# deploy/terraform/environments/*/versions.tf, which needs 1.10.0's native
# S3 conditional-write locking.
TOFU_IMAGE="ghcr.io/opentofu/opentofu@sha256:22cb52f6c5bf5c72a48a8f56d993d8df3e9462b1cdfb5db7e77143c87e8d159f"

# alpine:3. Used for one root-owned file operation at a time: chown a
# signature bundle, delete token state a root container created.
ALPINE_IMAGE="alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
TOFU_CLEANUP_IMAGE="$ALPINE_IMAGE"

# registry:2. The throwaway registry ci/signing-mechanism-test.sh pushes
# into. It lives for one run and is removed with it.
REGISTRY_IMAGE="registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"

# golang.org/x/vuln/cmd/govulncheck. A module version rather than an image:
# the module proxy's checksum database makes a released version immutable.
GOVULNCHECK_VERSION="v1.7.0"

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
