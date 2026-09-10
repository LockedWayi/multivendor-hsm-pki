#!/usr/bin/env bash
#
# Counter-sign a published image with the durable key, so that somebody who
# does not trust this repository can verify it.
#
#   HSM_PKI_TRUST_ANCHOR_REPO=... HSM_PKI_TRUST_ANCHOR_COMMIT=... HSM_PKI_TRUST_ANCHOR_SHA256=... \
#   COSIGN_PKCS11_PIN=... ci/countersign-release.sh ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:<digest>
#
# The pipeline signs every published digest keyless. That signature names
# the workflow that made it. It is not in the key inventory, so admission
# ignores it and ci/verify-release.sh does not accept it.
#
# This script adds what a release needs, all made by image-signing-key-v1
# on the maintainer's own token:
#
#   1. the image signature
#   2. the CycloneDX SBOM attestation
#   3. the SLSA provenance attestation
#
# The two predicates are not regenerated here. They are read back from the
# keyless attestations the pipeline attached, after the keyless identity is
# verified, so the durable key signs the statements the pipeline made. A
# digest with no keyless attestations is refused.
#
# Each of the three is skipped when the durable key already made it, so a
# run interrupted half way can be repeated. The success criterion is that
# ci/verify-release.sh passes afterwards.
#
# Environment:
#   COSIGN_PKCS11_PIN                          required
#   HSM_PKI_TRUST_ANCHOR_REPO, _COMMIT, _SHA256  required by ci/verify-release.sh
#   HSM_PKI_SIGNING_STATE      the token store, default .local/signing
#   HSM_PKI_DOCKER_CONFIG      registry credentials, default ~/.docker
#   HSM_PKI_IMAGE_KEY_LABEL    default image-signing-key-v1
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/keyless-identity.sh
. "$REPO_ROOT/ci/keyless-identity.sh"

die() { echo "countersign-release: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

REF="${1:-}"
[ -n "$REF" ] || die "usage: ci/countersign-release.sh <image>@sha256:<digest>"
case "$REF" in
    *@sha256:*) ;;
    *) die "refusing to sign a tag: $REF. A signature is made over a digest." ;;
esac
DIGEST="${REF#*@}"

[ -n "${COSIGN_PKCS11_PIN:-}" ] || die \
    "set COSIGN_PKCS11_PIN. The PIN reaches cosign as an environment variable and never inside a PKCS#11 URI."
for v in HSM_PKI_TRUST_ANCHOR_REPO HSM_PKI_TRUST_ANCHOR_COMMIT HSM_PKI_TRUST_ANCHOR_SHA256; do
    [ -n "${!v:-}" ] || die "$v is not set. ci/verify-release.sh needs the anchor inputs; see its header."
done

# Signing is a registry push, so cosign needs the operator's credentials.
if [ -z "${HSM_PKI_DOCKER_CONFIG:-}" ] && [ -d "$HOME/.docker" ]; then
    export HSM_PKI_DOCKER_CONFIG="$HOME/.docker"
fi
[ -n "${HSM_PKI_DOCKER_CONFIG:-}" ] || die \
    "no registry credentials. Run: docker login ghcr.io -u <you>   (a token with write:packages)"

STATE="${HSM_PKI_SIGNING_STATE:-$REPO_ROOT/.local/signing}"
KEYS_DIR="${HSM_PKI_KEYS_DIR:-$REPO_ROOT/docs/keys}"
[ "$KEYS_DIR" = "$REPO_ROOT/docs/keys" ] || die \
    "refusing to counter-sign with keys from $KEYS_DIR.
The durable signature is made by the key the published inventory lists,
which is the one in docs/keys."
KEY_LABEL="${HSM_PKI_IMAGE_KEY_LABEL:-image-signing-key-v1}"
PUBLIC_KEY="docs/keys/$KEY_LABEL.pub"
[ -f "$REPO_ROOT/$PUBLIC_KEY" ] || die "no public key at $PUBLIC_KEY"
export HSM_PKI_SIGNING_STATE="$STATE" HSM_PKI_KEYS_DIR="$KEYS_DIR"
export HSM_PKI_REGISTRY_ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-false}"

WORK="$REPO_ROOT/.local/countersign"
mkdir -p "$WORK"

log "checking the chain BEFORE counter-signing"
if "$REPO_ROOT/ci/verify-release.sh" "$REF" >/dev/null 2>&1; then
    echo "    already verifiable: signature and both attestations are in place."
    exit 0
fi
echo "    not verifiable yet"

# durable_present <subcommand> [args]: does the durable key already vouch?
durable_present() {
    HSM_PKI_COSIGN_VERSION=v2 HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" "$@" \
        --key "/repo/$PUBLIC_KEY" --insecure-ignore-tlog=true \
        --allow-http-registry="$HSM_PKI_REGISTRY_ALLOW_HTTP" "$REF" >/dev/null 2>&1
}

log "reading the pipeline's keyless attestations back from the registry"
# Verified against the workflow identity before anything is read out of
# them. cosign v3 reads the layout the pipeline wrote.
"$REPO_ROOT/ci/cosign.sh" fetch >/dev/null
fetch_predicate() {   # fetch_predicate <type> <out>
    local envelope="$WORK/$1.dsse.json"
    HSM_PKI_COSIGN_VERSION=v3 HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" verify-attestation \
        --certificate-identity-regexp "$KEYLESS_IDENTITY_REGEXP" \
        --certificate-oidc-issuer "$KEYLESS_OIDC_ISSUER" \
        --type "$1" --allow-http-registry="$HSM_PKI_REGISTRY_ALLOW_HTTP" \
        "$REF" > "$envelope" 2>/dev/null \
        || die "this digest carries no keyless $1 attestation from the pipeline.
Only digests the pipeline published are counter-signed."
    "$REPO_ROOT/ci/extract-predicate.sh" "$envelope" "$DIGEST" "$2"
}
fetch_predicate cyclonedx "$WORK/sbom.cdx.json"
fetch_predicate slsaprovenance1 "$WORK/provenance.json"
"$REPO_ROOT/ci/check-provenance.sh" <(printf '%s\n' "$(cat "$WORK/slsaprovenance1.dsse.json")") "$DIGEST" \
    "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"])' "$WORK/provenance.json")"

log "counter-signing with $KEY_LABEL on $STATE"
if durable_present verify; then
    echo "    signature already made by $KEY_LABEL, skipping"
else
    "$REPO_ROOT/ci/sign-image.sh" "$REF"
fi

log "re-attesting the SBOM and the provenance with $KEY_LABEL"
if durable_present verify-attestation --type cyclonedx && durable_present verify-attestation --type slsaprovenance1; then
    echo "    both attestations already made by $KEY_LABEL, skipping"
else
    "$REPO_ROOT/ci/attest-image.sh" "$REF" "$WORK/sbom.cdx.json" "$WORK/provenance.json"
fi

log "checking the chain AFTER counter-signing"
"$REPO_ROOT/ci/verify-release.sh" "$REF" || die \
    "counter-signed, but the independent verification still fails.
Investigate before announcing this digest as a release."

cat <<EOT

This digest is now verifiable by anyone who holds the anchor inputs:

  HSM_PKI_TRUST_ANCHOR_REPO=$HSM_PKI_TRUST_ANCHOR_REPO \\
  HSM_PKI_TRUST_ANCHOR_COMMIT=$HSM_PKI_TRUST_ANCHOR_COMMIT \\
  HSM_PKI_TRUST_ANCHOR_SHA256=$HSM_PKI_TRUST_ANCHOR_SHA256 \\
  ci/verify-release.sh $REF
EOT
