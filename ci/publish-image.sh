#!/usr/bin/env bash
#
# Build, scan, push and sign the service image (Phase 5.6).
#
#   ci/publish-image.sh <image-repository>
#
# e.g.  ci/publish-image.sh ghcr.io/lockedwayi/multivendor-hsm-pki
#
# Environment:
#   HSM_PKI_KEYS_DIR       where the public keys for this run live
#   HSM_PKI_SIGNING_STATE  the token store holding the signing keys
#   COSIGN_PKCS11_PIN      the token PIN, never on a command line
#   HSM_PKI_DOCKER_CONFIG  directory holding the registry credentials
#
# # The image is scanned HERE, not inherited from the gate that already
# # scanned one
#
# The `image` job earlier in this workflow builds the service image and runs
# trivy over it. It would be tempting to treat that as covering what this
# script pushes. It does not, and the reason is worth stating rather than
# discovering: a container build is not bit-reproducible -- the two jobs
# produce two builds of one commit, and nothing guarantees they share a
# digest. Publishing bytes that no scan ever examined, on the strength of a
# green check against *different* bytes, is exactly the shape of failure
# this repository keeps finding (a check that examined something else is
# indistinguishable, from the outside, from a check that examined this).
#
# So the same script the gate runs, ci/scan-image.sh, runs again here
# against the exact artifact about to leave the machine. It costs about a
# minute and it is the difference between a scanned image and a scanned
# sibling of one.
#
# # What identifies the thing being published
#
# The digest. Tags are addressing -- what an operator types -- and the
# digest is identity (CLAUDE.md 3.8). So the push is followed by resolving
# the digest, and everything downstream (the signature, the summary, what a
# consumer is told to verify) names the digest form.
#
# Two tags are written and no more:
#
#   sha-<commit>   an immutable pointer to the commit that produced this
#   v<x.y.z>       only when this exact commit carries that release tag
#
# Deliberately absent: `latest`, and a moving `main`. Both are pointers
# somebody can move, and this repository's whole argument about identity is
# that a name is not one. Somebody who wants the newest build reads the
# release notes and gets a digest.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "publish-image: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

IMAGE_REPO="${1:-}"
[ -n "$IMAGE_REPO" ] || die "usage: ci/publish-image.sh <image-repository>"

# Lowercase is a registry requirement rather than a style choice: ghcr.io
# rejects a path with an uppercase letter, and github.repository supplies
# one. Checked rather than silently folded, so the caller's intent is not
# quietly rewritten.
case "$IMAGE_REPO" in
    *[A-Z]*) die "image repository must be lowercase: $IMAGE_REPO" ;;
esac

[ -n "${COSIGN_PKCS11_PIN:-}" ] || die \
    "set COSIGN_PKCS11_PIN. The PIN reaches cosign as an environment
variable and never as pin-value= in a PKCS#11 URI -- a URI is a command
line argument, so it reaches ps output, shell history and any log that
echoes the command (CLAUDE.md 3.1)."

SHA="${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
SHA_TAG="sha-$SHA"

# --exact-match: a release tag applies to the commit that carries it and to
# no other. `git describe` without it reports the nearest ancestor tag,
# which would cheerfully label every commit after v0.1.0 as v0.1.0.
SEMVER_TAG=""
if SEMVER_TAG="$(git -C "$REPO_ROOT" describe --exact-match --tags "$SHA" 2>/dev/null)"; then
    log "this commit carries the release tag $SEMVER_TAG"
else
    SEMVER_TAG=""
    echo "no release tag on this commit; publishing under $SHA_TAG only"
fi

LOCAL_TAG="hsm-pki-server:publish"

# Plaintext to the registry is refused unless somebody says otherwise, and
# saying otherwise is per-environment rather than a default nobody reads.
# false is right for GHCR and every real registry; a local registry over
# HTTP is how this script is exercised without pushing to a public one.
ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-false}"

log "1/6  building the image this run will publish"
docker build -f "$REPO_ROOT/deploy/docker/Dockerfile" -t "$LOCAL_TAG" "$REPO_ROOT"

log "2/6  scanning the exact bytes about to be pushed"
# Fail closed: a HIGH or CRITICAL finding here stops the publish. The SBOM
# it writes on the way through is the one attached below, so the document
# describes the artifact rather than a rebuild of it.
"$REPO_ROOT/ci/scan-image.sh" "$LOCAL_TAG"

SBOM="${HSM_PKI_SCAN_OUT:-$REPO_ROOT/.local/scan}/sbom.cdx.json"
[ -f "$SBOM" ] || die "ci/scan-image.sh produced no SBOM at $SBOM"

log "3/6  pushing $IMAGE_REPO:$SHA_TAG"
docker tag "$LOCAL_TAG" "$IMAGE_REPO:$SHA_TAG"
docker push "$IMAGE_REPO:$SHA_TAG"

# Asked of the registry rather than assumed from the build: what a consumer
# pulls is what the registry holds.
DIGEST="$(docker inspect "$IMAGE_REPO:$SHA_TAG" \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    | grep "^$IMAGE_REPO@" | head -1 | cut -d@ -f2 || true)"
[ -n "$DIGEST" ] || die \
    "could not resolve $IMAGE_REPO:$SHA_TAG to a registry digest after
pushing it. Signing the local image instead would attest to bytes nobody
can fetch."
DIGEST_REF="$IMAGE_REPO@$DIGEST"
echo "    $DIGEST_REF"

if [ -n "$SEMVER_TAG" ]; then
    log "4/6  pushing the release tag $SEMVER_TAG at the same digest"
    docker tag "$LOCAL_TAG" "$IMAGE_REPO:$SEMVER_TAG"
    docker push "$IMAGE_REPO:$SEMVER_TAG"
else
    log "4/6  no release tag on this commit -- skipping the semver tag"
fi

log "5/6  signing $DIGEST_REF"
# By digest, never by tag. ci/sign-image.sh takes it from here: it signs
# with image-signing-key-v1 over PKCS#11 and refuses to leave a signature
# the published public key cannot verify.
HSM_PKI_REGISTRY_ALLOW_HTTP="$ALLOW_HTTP" "$REPO_ROOT/ci/sign-image.sh" "$DIGEST_REF"

log "6/6  attaching the SBOM as a signed attestation"
# `cosign attest`, not the older `cosign attach sbom`. attach writes the
# document beside the image unsigned, which makes it a text file anybody
# can replace; attest signs a statement about *this digest* with the same
# HSM-held key that signed the image, so the SBOM inherits the signature's
# custody rather than sitting next to it unauthenticated.
export HSM_PKI_COSIGN_VERSION=v2
HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" attest \
    --key "pkcs11:token=${HSM_PKI_SUPPLY_TOKEN:-hsm-pki-local-supply-chain};object=image-signing-key-v1" \
    --type cyclonedx \
    --predicate "/repo/$(realpath --relative-to="$REPO_ROOT" -- "$SBOM")" \
    --tlog-upload=false -y \
    --allow-http-registry="$ALLOW_HTTP" \
    "$DIGEST_REF"

cat <<EOF

Published and signed:

  $DIGEST_REF
  tags: $SHA_TAG${SEMVER_TAG:+, $SEMVER_TAG}

The digest is the identity. A consumer should pull the digest form above;
the tags are there to be typed, not to be trusted.

EOF
