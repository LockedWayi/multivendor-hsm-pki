#!/usr/bin/env bash
#
# Sign a container image with the image-signing key over PKCS#11, by
# digest, and refuse to leave a signature the published key cannot verify.
#
#   ci/sign-image.sh <image-reference>
#
# The reference may be a tag; what gets signed never is. A tag is resolved
# against the registry first and the digest form reaches cosign.
#
# The key signs images and nothing else. The release binary is signed by
# artifact-signing-key-v1 and certificates by the CA. The verification
# below is repeated with the artifact key in
# deploy/k8s/policy/policy-selftest.py, and it fails.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_LABEL="${HSM_PKI_IMAGE_KEY_LABEL:-image-signing-key-v1}"
TOKEN_LABEL="${HSM_PKI_SUPPLY_TOKEN:-hsm-pki-local-supply-chain}"
# The published public key, named relative to the repository because the
# signing container mounts the repository at /repo. Overridable for the
# mechanism test, which signs with keys it provisioned for the run.
KEYS_DIR="${HSM_PKI_KEYS_DIR:-$REPO_ROOT/docs/keys}"
case "$KEYS_DIR" in
    "$REPO_ROOT"/*) PUBLIC_KEY="${KEYS_DIR#"$REPO_ROOT"/}/$KEY_LABEL.pub" ;;
    *)
        echo "sign-image: HSM_PKI_KEYS_DIR must be inside $REPO_ROOT --" >&2
        echo "the signing container mounts only the repository, so a path" >&2
        echo "outside it resolves against the container's own filesystem." >&2
        exit 1 ;;
esac
# The local k3d registry speaks HTTP. Set to false against a real registry.
ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-true}"

die() { echo "sign-image: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

REF="${1:-}"
[ -n "$REF" ] || die "usage: ci/sign-image.sh <image-reference>"
[ -n "${COSIGN_PKCS11_PIN:-}" ] || die \
    "set COSIGN_PKCS11_PIN. The PIN reaches cosign as an environment
variable and never as pin-value= in the PKCS#11 URI."

case "$REF" in
    *@sha256:*)
        DIGEST_REF="$REF" ;;
    *)
        log "resolving $REF to a digest"
        # The tag is the colon after the last slash, not the first colon,
        # which in localhost:5000/repo:tag is the port.
        name="${REF##*/}"
        if [ "$name" != "${name%:*}" ]; then
            REPO="${REF%:*}"
        else
            REPO="$REF"
        fi
        # Asked of the registry: what will be pulled is what the registry
        # holds.
        digest="$(docker inspect "$REF" --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null \
            | grep "^$REPO@" | head -1 | cut -d@ -f2 || true)"
        [ -n "$digest" ] || die \
            "could not resolve $REF to a digest in repository $REPO. Push it
first -- an image that exists only locally has no digest in the registry the
cluster will pull from, and signing the local one would attest to bytes
nobody can fetch."
        DIGEST_REF="$REPO@$digest"
        echo "    $DIGEST_REF" ;;
esac

# cosign v2. v3 attaches an image signature as an OCI referrers artifact,
# and Kyverno v1.19's verifier looks for sha256-<digest>.sig, which v2
# writes.
export HSM_PKI_COSIGN_VERSION=v2

log "signing with $KEY_LABEL on token $TOKEN_LABEL (cosign ${HSM_PKI_COSIGN_VERSION})"
# v2 says "no transparency log" with --tlog-upload=false. -y skips a
# prompt that would hang an unattended run.
HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" sign \
    --key "pkcs11:token=$TOKEN_LABEL;object=$KEY_LABEL" \
    --tlog-upload=false -y \
    --allow-http-registry="$ALLOW_HTTP" \
    "$DIGEST_REF"

log "verifying with the published public key, which needs no HSM and no PIN"
# Checked back with the key a verifier would use. If the two disagree, the
# published key is not the one signing.
HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" verify \
    --key "/repo/$PUBLIC_KEY" \
    --insecure-ignore-tlog=true \
    --allow-http-registry="$ALLOW_HTTP" \
    "$DIGEST_REF" >/dev/null 2>&1 \
    || die "the signature does not verify against $PUBLIC_KEY.
The image is signed and nothing that consumes the inventory can check it."

cat <<EOF

Signed and verified:

  $DIGEST_REF

Verify it with the public key this signature was checked against, which
needs no HSM and no PIN:

  cosign verify --key $PUBLIC_KEY --insecure-ignore-tlog=true $DIGEST_REF

Admission accepts it wherever deploy/k8s/policy/image-signature.yaml is
installed if the key above is the durable key listed in
docs/keys/key-inventory.json. A key the mechanism test provisioned is not
in the inventory, so admission refuses an image it signed.

Regenerate the policy after any rotation:

  go run ./ci/generate-image-policy -out deploy/k8s/policy/image-signature.yaml
EOF
