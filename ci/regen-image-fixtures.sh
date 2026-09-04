#!/usr/bin/env bash
#
# Put the image fixtures deploy/k8s/policy/image-policy-selftest.py needs
# into the local k3d registry, and print the digests it should reference.
#
#   ci/regen-image-fixtures.sh
#
# Four repositories, differing only in what has been signed and by which
# key. Three of them hold the *same bytes*, which is the point: a cosign
# signature is stored per repository, so identical content is signed in one
# place, signed by the wrong key in another, and unsigned in a third. That
# is what lets the suite test the signature rule without the image content
# being a variable.
#
#   signed      busybox, signed by image-signing-key-v1     must be admitted
#   wrongkey    busybox, signed by artifact-signing-key-v1  wrong purpose
#   unsigned    busybox, not signed                         no signature
#
# The service's own image is signed by ci/sign-image.sh as part of
# deploy/k8s/overlays/dev/k3d-up.sh and is not recreated here.
#
# Digests are read back from the registry rather than from `docker inspect`.
# They differ: the local daemon reports the digest of the manifest it holds,
# which for a multi-architecture base is the index, while the registry
# reports what it stored on push. Using the local one produced
# MANIFEST_UNKNOWN from admission -- a fixture that looked right and named
# an image the cluster could not resolve.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY_FROM_HOST="${HSM_PKI_REGISTRY_HOST:-localhost:5000}"
BASE_IMAGE="busybox:1.36"

[ -n "${COSIGN_PKCS11_PIN:-}" ] || {
    echo "set COSIGN_PKCS11_PIN: two of these fixtures are signed over the HSM" >&2
    exit 1
}

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

registry_digest() {
    curl -sS -I \
        -H 'Accept: application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json' \
        "http://$REGISTRY_FROM_HOST/v2/$1/manifests/probe" 2>/dev/null \
        | grep -i '^docker-content-digest' | tr -d '\r' | awk '{print $2}'
}

sign_with() {   # sign_with <key-label> <repo@digest>
    HSM_PKI_COSIGN_VERSION=v2 HSM_PKI_COSIGN_NETWORK=host \
        "$REPO_ROOT/ci/cosign.sh" sign \
        --key "pkcs11:token=${HSM_PKI_SUPPLY_TOKEN:-hsm-pki-local-supply-chain};object=$1" \
        --tlog-upload=false -y --allow-http-registry=true "$2" >/dev/null 2>&1
}

log "pushing $BASE_IMAGE into three repositories"
docker pull -q "$BASE_IMAGE" >/dev/null
for repo in signed wrongkey unsigned; do
    docker tag "$BASE_IMAGE" "$REGISTRY_FROM_HOST/$repo:probe"
    docker push -q "$REGISTRY_FROM_HOST/$repo:probe" >/dev/null
done

SIGNED_DIGEST="$(registry_digest signed)"
WRONG_DIGEST="$(registry_digest wrongkey)"
UNSIGNED_DIGEST="$(registry_digest unsigned)"
for d in "$SIGNED_DIGEST" "$WRONG_DIGEST" "$UNSIGNED_DIGEST"; do
    [ -n "$d" ] || { echo "the registry did not report a digest; is it running?" >&2; exit 1; }
done

log "signing two of them, with different keys"
sign_with image-signing-key-v1    "$REGISTRY_FROM_HOST/signed@$SIGNED_DIGEST"
sign_with artifact-signing-key-v1 "$REGISTRY_FROM_HOST/wrongkey@$WRONG_DIGEST"

cat <<EOF

Fixtures ready. deploy/k8s/policy/image-policy-selftest.py should reference:

  SIGNED_BUSYBOX = "signed@$SIGNED_DIGEST"
  WRONG_KEY      = "wrongkey@$WRONG_DIGEST"
  UNSIGNED       = "unsigned@$UNSIGNED_DIGEST"
EOF
