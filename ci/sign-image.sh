#!/usr/bin/env bash
#
# Sign a container image over the HSM, by digest, and refuse to emit a
# signature the published key cannot verify (Phase 4.10).
#
#   ci/sign-image.sh <image-reference>
#
# The reference may be a tag; what gets signed never is. A signature is made
# over a digest, and a tag is a mutable pointer -- signing "the thing this
# name points at right now" attests to nothing that survives the next push
# (CLAUDE.md §3.8). So the tag is resolved against the registry first and the
# digest form is what reaches cosign, and what the message prints.
#
# The key is image-signing-key-v1 on the supply-chain token. It signs images
# and nothing else: the release binary is signed by artifact-signing-key-v1
# and certificates by the CA, because a compromise of one must not be able to
# do the others' job (CLAUDE.md §3.6). Proven rather than asserted -- the
# verification below is repeated with the artifact key in
# deploy/k8s/policy/policy-selftest.py, and it fails.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_LABEL="image-signing-key-v1"
TOKEN_LABEL="${HSM_PKI_SUPPLY_TOKEN:-hsm-pki-local-supply-chain}"
PUBLIC_KEY="docs/keys/$KEY_LABEL.pub"
# The local k3d registry speaks HTTP. Set to false against a real registry;
# it is a flag rather than a constant so that "we allow plaintext" is a
# decision somebody makes per environment rather than a default nobody sees.
ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-true}"

die() { echo "sign-image: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

REF="${1:-}"
[ -n "$REF" ] || die "usage: ci/sign-image.sh <image-reference>"
[ -n "${COSIGN_PKCS11_PIN:-}" ] || die \
    "set COSIGN_PKCS11_PIN. The PIN reaches cosign as an environment
variable and never as pin-value= in the PKCS#11 URI (CLAUDE.md §3.1)."

case "$REF" in
    *@sha256:*)
        DIGEST_REF="$REF" ;;
    *)
        log "resolving $REF to a digest"
        # The repository is the reference minus its tag, and the tag is the
        # colon *after the last slash* -- not the first colon in the string,
        # which in localhost:5000/hsm-pki-server:local is the registry's
        # port. Stripping at the first colon yields "localhost", which
        # matches nothing and reports the image as unpushed. Found by
        # running it.
        name="${REF##*/}"
        if [ "$name" != "${name%:*}" ]; then
            REPO="${REF%:*}"
        else
            REPO="$REF"
        fi
        # Asked of the registry rather than of the local daemon: what will
        # be pulled is what the registry holds, and a local image that has
        # drifted from it would otherwise be signed under the registry's name.
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

# cosign v2, not v3, and the reason is measured. v3 attaches an image
# signature as an OCI referrers artifact -- under the fallback tag
# sha256-<digest> when the registry has no referrers API -- while Kyverno
# v1.19's cosign verifier looks for sha256-<digest>.sig and reports "no
# signatures found" against a signature cosign itself verifies happily.
# Neither side has a flag that bridges it. Release artifacts still use v3,
# whose bundle is what internal/artifactsig reads; both versions are pinned
# and verified identically by ci/cosign.sh.
export HSM_PKI_COSIGN_VERSION=v2

log "signing with $KEY_LABEL on token $TOKEN_LABEL (cosign ${HSM_PKI_COSIGN_VERSION})"
# v2 has no --signing-config; its way of saying "no transparency log" is
# --tlog-upload=false, which v3 refuses. The two tracks differ here and the
# difference is per track rather than per environment, so it lives with the
# version choice above. -y because there is nothing interactive to confirm
# in a signing step, and an unattended prompt is a hang, not a safeguard.
HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" sign \
    --key "pkcs11:token=$TOKEN_LABEL;object=$KEY_LABEL" \
    --tlog-upload=false -y \
    --allow-http-registry="$ALLOW_HTTP" \
    "$DIGEST_REF"

log "verifying with the published public key, which needs no HSM and no PIN"
# The signature is checked back with the key a verifier would use, not with
# the token that made it. If these two ever disagree, the published key is
# not the one signing, and every consumer of the inventory is verifying
# against the wrong thing.
HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" verify \
    --key "/repo/$PUBLIC_KEY" \
    --insecure-ignore-tlog=true \
    --allow-http-registry="$ALLOW_HTTP" \
    "$DIGEST_REF" >/dev/null 2>&1 \
    || die "the signature does not verify against $PUBLIC_KEY.
The image is signed but nothing that consumes the inventory can check it,
which is worse than unsigned: it looks protected and is not."

cat <<EOF

Signed and verified:

  $DIGEST_REF

Admission will accept it wherever deploy/k8s/policy/image-signature.yaml is
installed, because $KEY_LABEL is listed in docs/keys/key-inventory.json.
Regenerate that policy after any rotation:

  go run ./ci/generate-image-policy -out deploy/k8s/policy/image-signature.yaml
EOF
