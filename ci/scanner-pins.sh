# Pinned scanner references, in one place because two scripts need them and
# a scanner that differs between them turns "the findings changed" into two
# questions instead of one.
#
# Digests, not tags. ci.yml already pins its actions by commit SHA and the
# gitleaks image by digest for the reason CLAUDE.md §3.8 gives: a tag is a
# pointer somebody else can move, so a tag-pinned scanner is a scanner
# whose version is decided by its publisher after review. The tag beside
# each digest is for a human reading the file; Docker resolves the digest.
#
# Sourced, never executed: `. "$(dirname "$0")/scanner-pins.sh"`.

# aquasec/trivy:0.67.0
TRIVY_IMAGE="aquasec/trivy@sha256:94711c60051c6cab848a292e3a67f62623fcee361b2bb661f43b17184f4afdac"

# semgrep/semgrep:1.175.1
SEMGREP_IMAGE="semgrep/semgrep@sha256:51c9f53a4fce0d55e9abd08d7b96968654248a4b1122e77f20e0a49c0072446c"

# ghcr.io/opentofu/opentofu:1.12.6 -- must stay >= the required_version in
# deploy/terraform/environments/*/versions.tf, which depends on 1.10.0's
# native S3 conditional-write locking.
TOFU_IMAGE="ghcr.io/opentofu/opentofu@sha256:22cb52f6c5bf5c72a48a8f56d993d8df3e9462b1cdfb5db7e77143c87e8d159f"

# alpine:3 -- used only to delete root-owned files a root container created
# inside the checkout. Any image with a shell would do; pinned by digest
# anyway, because "it only runs rm" is how an unpinned image gets into a
# repository that has a rule against them.
TOFU_CLEANUP_IMAGE="alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

# golang.org/x/vuln/cmd/govulncheck. A module version rather than an image:
# the Go module proxy's checksum database makes a released version
# immutable in the same way a digest does.
GOVULNCHECK_VERSION="v1.7.0"

# buildGoImage prints the exact builder image the shipped binary is compiled
# with, read out of the service Dockerfile rather than copied from it.
#
# This matters for govulncheck specifically. Part of its answer is about the
# Go standard library, and *which* standard library is a property of the
# toolchain doing the build -- so a scan run on the runner's own Go answers
# a question about a toolchain that never ships. Reading the digest here
# means bumping the builder in deploy/docker/Dockerfile moves the scan with
# it, instead of leaving a second copy to drift.
buildGoImage() {
    local dockerfile="$1" matches
    matches="$(grep -cE '^FROM golang:[^ ]+@sha256:[0-9a-f]{64} AS build$' "$dockerfile" || true)"
    if [ "$matches" != "1" ]; then
        # Fail closed (CLAUDE.md §3.4): guessing a toolchain here would
        # silently scan the wrong standard library.
        echo "scanner-pins: expected exactly one digest-pinned 'AS build' stage in $dockerfile, found $matches" >&2
        return 1
    fi
    sed -nE 's/^FROM (golang:[^ ]+@sha256:[0-9a-f]{64}) AS build$/\1/p' "$dockerfile"
}
