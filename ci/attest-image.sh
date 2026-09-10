#!/usr/bin/env bash
#
# Attach the SBOM and the SLSA provenance to an image as attestations
# signed by the image-signing key over PKCS#11, then check each one back
# with the published public key.
#
#   ci/attest-image.sh <image>@sha256:<digest> <sbom.cdx.json> <provenance.json>
#
# Environment is the same as ci/sign-image.sh: COSIGN_PKCS11_PIN,
# HSM_PKI_KEYS_DIR, HSM_PKI_SIGNING_STATE, HSM_PKI_SUPPLY_TOKEN,
# HSM_PKI_IMAGE_KEY_LABEL, HSM_PKI_REGISTRY_ALLOW_HTTP, HSM_PKI_DOCKER_CONFIG.
#
# cosign attest, not cosign attach. attach writes the document beside the
# image unsigned. attest signs a statement whose subject is this digest.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_LABEL="${HSM_PKI_IMAGE_KEY_LABEL:-image-signing-key-v1}"
TOKEN_LABEL="${HSM_PKI_SUPPLY_TOKEN:-hsm-pki-local-supply-chain}"
KEYS_DIR="${HSM_PKI_KEYS_DIR:-$REPO_ROOT/docs/keys}"
ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-false}"

die() { echo "attest-image: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

case "$KEYS_DIR" in
    "$REPO_ROOT"/*) PUBLIC_KEY="${KEYS_DIR#"$REPO_ROOT"/}/$KEY_LABEL.pub" ;;
    *) die "HSM_PKI_KEYS_DIR must be inside $REPO_ROOT: the signing container mounts only the repository" ;;
esac

REF="${1:-}"
SBOM="${2:-}"
PROVENANCE="${3:-}"
[ -n "$REF" ] && [ -n "$SBOM" ] && [ -n "$PROVENANCE" ] \
    || die "usage: ci/attest-image.sh <image>@sha256:<digest> <sbom.cdx.json> <provenance.json>"
case "$REF" in
    *@sha256:*) ;;
    *) die "refusing to attest a tag: $REF. An attestation is bound to a digest." ;;
esac
[ -n "${COSIGN_PKCS11_PIN:-}" ] || die \
    "set COSIGN_PKCS11_PIN. The PIN reaches cosign as an environment variable and never inside a PKCS#11 URI."

rel() {
    local resolved
    resolved="$(realpath -m -- "$1")"
    case "$resolved" in
        "$REPO_ROOT"/*) printf '%s' "${resolved#"$REPO_ROOT"/}" ;;
        *) die "$1 is outside the repository at $REPO_ROOT. The signing container mounts only the repository." ;;
    esac
}
SBOM_REL="$(rel "$SBOM")"
PROV_REL="$(rel "$PROVENANCE")"
[ -f "$SBOM" ] || die "no SBOM at $SBOM"
[ -f "$PROVENANCE" ] || die "no provenance predicate at $PROVENANCE"

export HSM_PKI_COSIGN_VERSION=v2

attest() {   # attest <type> <predicate rel path>
    log "attesting $1 with $KEY_LABEL on token $TOKEN_LABEL"
    HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" attest \
        --key "pkcs11:token=$TOKEN_LABEL;object=$KEY_LABEL" \
        --type "$1" --predicate "/repo/$2" \
        --tlog-upload=false -y \
        --allow-http-registry="$ALLOW_HTTP" \
        "$REF"
    HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" verify-attestation \
        --key "/repo/$PUBLIC_KEY" --type "$1" \
        --insecure-ignore-tlog=true \
        --allow-http-registry="$ALLOW_HTTP" \
        "$REF" >/dev/null 2>&1 \
        || die "the $1 attestation does not verify against $PUBLIC_KEY.
It is attached and nothing that consumes the inventory can check it."
    echo "    verified with $PUBLIC_KEY"
}

attest cyclonedx "$SBOM_REL"
attest slsaprovenance1 "$PROV_REL"

cat <<EOT

Attested and verified:

  $REF
  cyclonedx        $SBOM_REL
  slsaprovenance1  $PROV_REL
EOT
