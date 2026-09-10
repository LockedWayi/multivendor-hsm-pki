#!/usr/bin/env bash
#
# Build, scan, prove the PKCS#11 signing path, then push and sign the
# service image keyless.
#
#   ci/publish-image.sh <image-repository>
#
# e.g.  ci/publish-image.sh ghcr.io/lockedwayi/multivendor-hsm-pki
#
# Steps:
#   1. build the image
#   2. scan it; the SBOM written here is the one attested below
#   3. ci/signing-mechanism-test.sh signs the same image with a throwaway
#      PKCS#11 token into a throwaway registry and verifies everything. A
#      regression in the PKCS#11 signing path stops the publish here.
#   4. push the bytes under the staging tag
#   5. sign the digest keyless; attest the SBOM and the provenance keyless
#   6. apply sha-<commit>, and v<x.y.z> when the commit carries that tag
#   7. extract the binary from the signed image and sign it keyless
#
# Keyless: cosign obtains a short-lived certificate from Fulcio for this
# workflow run's OIDC identity and records the signature in Rekor. The
# identity is the workflow file at the ref that ran; see
# ci/keyless-identity.sh. Nothing pushed to the registry is signed by a
# PKCS#11 key here. The durable signature is added by the maintainer with
# ci/countersign-release.sh.
#
# Tags. The bytes go up under `staging`, one moving tag that always names
# the most recent build pushed, signed or not. sha-<commit> and v<x.y.z>
# are applied only after the signature and both attestations exist, so
# they only ever name a signed digest. There is no latest and no main.
#
# Environment:
#   HSM_PKI_DOCKER_CONFIG        directory holding the registry credentials
#   HSM_PKI_REGISTRY_ALLOW_HTTP  plaintext registry, default false
#   GITHUB_*                     the pipeline's variables; provenance and
#                                the keyless identity are built from them
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/keyless-identity.sh
. "$REPO_ROOT/ci/keyless-identity.sh"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"

die() { echo "publish-image: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

IMAGE_REPO="${1:-}"
[ -n "$IMAGE_REPO" ] || die "usage: ci/publish-image.sh <image-repository>"
case "$IMAGE_REPO" in
    *[A-Z]*) die "image repository must be lowercase: $IMAGE_REPO" ;;
esac
[ -z "${COSIGN_PKCS11_PIN:-}" ] || die \
    "COSIGN_PKCS11_PIN is set. This script signs keyless and holds no PIN.
The PKCS#11 mechanism test generates its own."
[ -n "${GITHUB_WORKFLOW_REF:-}" ] || die \
    "GITHUB_WORKFLOW_REF is not set. Keyless signing needs the pipeline's OIDC
identity; there is nothing to sign with outside a workflow run."

SHA="${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
SHA_TAG="sha-$SHA"
SEMVER_TAG=""
# --exact-match: the release tag applies to the commit that carries it and
# to no other.
if SEMVER_TAG="$(git -C "$REPO_ROOT" describe --exact-match --tags "$SHA" 2>/dev/null)"; then
    log "this commit carries the release tag $SEMVER_TAG"
else
    SEMVER_TAG=""
    echo "no release tag on this commit; publishing under $SHA_TAG only"
fi

LOCAL_TAG="hsm-pki-server:publish"
STAGING_TAG="staging"
ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-false}"
IDENTITY="https://github.com/$GITHUB_WORKFLOW_REF"

log "1/7  building the image"
docker build -f "$REPO_ROOT/deploy/docker/Dockerfile" -t "$LOCAL_TAG" "$REPO_ROOT"

log "2/7  scanning the exact bytes about to be pushed"
# The image gate scanned a different build of the same commit. A container
# build is not bit-reproducible, so the bytes pushed here are scanned again.
"$REPO_ROOT/ci/scan-image.sh" "$LOCAL_TAG"
SBOM="${HSM_PKI_SCAN_OUT:-$REPO_ROOT/.local/scan}/sbom.cdx.json"
[ -f "$SBOM" ] || die "ci/scan-image.sh produced no SBOM at $SBOM"

log "3/7  proving the PKCS#11 signing path against a throwaway registry"
"$REPO_ROOT/ci/signing-mechanism-test.sh" "$LOCAL_TAG" "$SBOM"

log "4/7  pushing the bytes under $STAGING_TAG"
docker tag "$LOCAL_TAG" "$IMAGE_REPO:$STAGING_TAG"
docker push "$IMAGE_REPO:$STAGING_TAG"
DIGEST="$(docker inspect "$IMAGE_REPO:$STAGING_TAG" \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    | grep "^$IMAGE_REPO@" | head -1 | cut -d@ -f2 || true)"
[ -n "$DIGEST" ] || die "could not resolve $IMAGE_REPO:$STAGING_TAG to a registry digest after pushing it."
DIGEST_REF="$IMAGE_REPO@$DIGEST"
echo "    $DIGEST_REF"

log "5/7  signing and attesting keyless as $IDENTITY"
PROVENANCE="${HSM_PKI_SCAN_OUT:-$REPO_ROOT/.local/scan}/provenance.json"
"$REPO_ROOT/ci/generate-provenance.sh" "$PROVENANCE"

# cosign v3 for every keyless operation. It takes the service URLs from
# Sigstore's TUF-distributed signing config, so the pipeline follows the
# public instance when it moves.
export HSM_PKI_COSIGN_VERSION=v3 HSM_PKI_COSIGN_MODE=keyless HSM_PKI_COSIGN_NETWORK=host
"$REPO_ROOT/ci/cosign.sh" fetch >/dev/null
keyless() { "$REPO_ROOT/ci/cosign.sh" "$@"; }
verify_keyless() {   # verify_keyless <subcommand> [args] <ref>
    "$REPO_ROOT/ci/cosign.sh" "$@" \
        --certificate-identity "$IDENTITY" \
        --certificate-oidc-issuer "$KEYLESS_OIDC_ISSUER"
}

keyless sign --yes --allow-http-registry="$ALLOW_HTTP" "$DIGEST_REF"
verify_keyless verify --allow-http-registry="$ALLOW_HTTP" "$DIGEST_REF" >/dev/null \
    || die "the keyless signature does not verify for identity $IDENTITY"
echo "    signature       verified for $IDENTITY"

keyless attest --yes --type cyclonedx \
    --predicate "/repo/$(realpath --relative-to="$REPO_ROOT" -- "$SBOM")" \
    --allow-http-registry="$ALLOW_HTTP" "$DIGEST_REF"
verify_keyless verify-attestation --type cyclonedx --allow-http-registry="$ALLOW_HTTP" "$DIGEST_REF" >/dev/null \
    || die "the keyless SBOM attestation does not verify for identity $IDENTITY"
echo "    SBOM            verified"

keyless attest --yes --type slsaprovenance1 \
    --predicate "/repo/$(realpath --relative-to="$REPO_ROOT" -- "$PROVENANCE")" \
    --allow-http-registry="$ALLOW_HTTP" "$DIGEST_REF"
ENVELOPE="${HSM_PKI_SCAN_OUT:-$REPO_ROOT/.local/scan}/provenance.dsse.json"
verify_keyless verify-attestation --type slsaprovenance1 --allow-http-registry="$ALLOW_HTTP" "$DIGEST_REF" > "$ENVELOPE" \
    || die "the keyless provenance attestation does not verify for identity $IDENTITY"
"$REPO_ROOT/ci/check-provenance.sh" "$ENVELOPE" "$DIGEST" "$SHA"
echo "    provenance      verified"

log "6/7  applying the release tags now that the digest is signed"
for t in "$SHA_TAG" ${SEMVER_TAG:+"$SEMVER_TAG"}; do
    docker tag "$LOCAL_TAG" "$IMAGE_REPO:$t"
    docker push "$IMAGE_REPO:$t"
    echo "    $IMAGE_REPO:$t -> $DIGEST"
done

log "7/7  extracting the binary from the signed image and signing it keyless"
# Extracted, not rebuilt: a second go build could produce different bytes.
RELEASE_DIR="$REPO_ROOT/.local/release"
mkdir -p "$RELEASE_DIR"
BINARY="$RELEASE_DIR/hsm-pki-server"
BUNDLE="$BINARY.sigstore.json"
cid="$(docker create "$LOCAL_TAG")"
docker cp "$cid:/usr/local/bin/hsm-pki-server" "$BINARY" >/dev/null
docker rm -f "$cid" >/dev/null
chmod 0755 "$BINARY"
rm -f "$BUNDLE"
keyless sign-blob --yes \
    --bundle "/repo/${BUNDLE#"$REPO_ROOT"/}" \
    "/repo/${BINARY#"$REPO_ROOT"/}"
# cosign ran as root in its container, so the bundle is root-owned.
docker run --rm -v "$RELEASE_DIR":/out "$ALPINE_IMAGE" chown "$(id -u):$(id -g)" /out/hsm-pki-server.sigstore.json
chmod 0644 "$BUNDLE"
verify_keyless verify-blob --bundle "/repo/${BUNDLE#"$REPO_ROOT"/}" "/repo/${BINARY#"$REPO_ROOT"/}" >/dev/null \
    || die "the keyless binary signature does not verify for identity $IDENTITY"
(cd "$RELEASE_DIR" && sha256sum hsm-pki-server) > "$BINARY.sha256"
echo "    $(cat "$BINARY.sha256")"

cat <<EOT

Published and signed keyless:

  $DIGEST_REF
  tags       $SHA_TAG${SEMVER_TAG:+, $SEMVER_TAG}, staging
  identity   $IDENTITY
  binary     $(cut -d' ' -f1 "$BINARY.sha256")

The digest is the identity of the image. A consumer pulls the digest form.
This digest is not yet counter-signed by the durable key; a release is,
through ci/countersign-release.sh.
EOT
