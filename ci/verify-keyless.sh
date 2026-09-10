#!/usr/bin/env bash
#
# Verify the keyless signature, both keyless attestations and, when given,
# the keyless-signed binary of one published digest.
#
#   ci/verify-keyless.sh <image>@sha256:<digest> [--commit <sha>] [--binary <path> --bundle <path>]
#
# This is what the verifyrun job runs after every publish, from a checkout
# that holds no key material. A consumer can run the same cosign commands
# by hand; the README lists them.
#
# Environment:
#   HSM_PKI_KEYLESS_IDENTITY     the exact certificate identity to require.
#                                Default: the regular expression in
#                                ci/keyless-identity.sh, which admits a main
#                                build or a release tag.
#   HSM_PKI_REGISTRY_ALLOW_HTTP  plaintext registry, default false
#
# Rekor inclusion is checked by cosign. Nothing here passes
# --insecure-ignore-tlog.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/keyless-identity.sh
. "$REPO_ROOT/ci/keyless-identity.sh"

die() { echo "verify-keyless: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

REF="${1:-}"
[ -n "$REF" ] || die "usage: ci/verify-keyless.sh <image>@sha256:<digest> [--commit <sha>] [--binary <path> --bundle <path>]"
shift
case "$REF" in
    *@sha256:*) ;;
    *) die "refusing to verify a tag: $REF. Pass the digest form." ;;
esac
DIGEST="${REF#*@}"

COMMIT="${GITHUB_SHA:-}"
BINARY=""
BUNDLE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --commit) COMMIT="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        --bundle) BUNDLE="$2"; shift 2 ;;
        *) die "unknown argument $1" ;;
    esac
done
[ -n "$COMMIT" ] || COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-false}"

identity_args=(--certificate-oidc-issuer "$KEYLESS_OIDC_ISSUER")
if [ -n "${HSM_PKI_KEYLESS_IDENTITY:-}" ]; then
    identity_args+=(--certificate-identity "$HSM_PKI_KEYLESS_IDENTITY")
    echo "identity  $HSM_PKI_KEYLESS_IDENTITY"
else
    identity_args+=(--certificate-identity-regexp "$KEYLESS_IDENTITY_REGEXP")
    echo "identity  $KEYLESS_IDENTITY_REGEXP"
fi
echo "issuer    $KEYLESS_OIDC_ISSUER"

rel() {
    local resolved
    resolved="$(realpath -m -- "$1")"
    case "$resolved" in
        "$REPO_ROOT"/*) printf '%s' "${resolved#"$REPO_ROOT"/}" ;;
        *) die "$1 is outside the repository at $REPO_ROOT. cosign runs in a container that mounts only the repository." ;;
    esac
}

WORK="$REPO_ROOT/.local/verify-keyless"
mkdir -p "$WORK"

export HSM_PKI_COSIGN_VERSION=v3
"$REPO_ROOT/ci/cosign.sh" fetch >/dev/null
cosign() { HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" "$@"; }

log "1/4  the image signature"
cosign verify "${identity_args[@]}" --allow-http-registry="$ALLOW_HTTP" "$REF" >/dev/null \
    || die "no keyless signature by the expected identity on $REF"
echo "    verified"

log "2/4  the CycloneDX SBOM attestation"
cosign verify-attestation "${identity_args[@]}" --type cyclonedx --allow-http-registry="$ALLOW_HTTP" "$REF" >/dev/null \
    || die "no keyless SBOM attestation by the expected identity on $REF"
echo "    verified"

log "3/4  the SLSA provenance attestation, and what it says"
ENVELOPE="$WORK/provenance.dsse.json"
cosign verify-attestation "${identity_args[@]}" --type slsaprovenance1 --allow-http-registry="$ALLOW_HTTP" "$REF" > "$ENVELOPE" \
    || die "no keyless provenance attestation by the expected identity on $REF"
"$REPO_ROOT/ci/check-provenance.sh" "$ENVELOPE" "$DIGEST" "$COMMIT"

if [ -n "$BINARY" ] || [ -n "$BUNDLE" ]; then
    [ -n "$BINARY" ] && [ -n "$BUNDLE" ] || die "--binary and --bundle go together"
    log "4/4  the release binary"
    cosign verify-blob "${identity_args[@]}" --bundle "/repo/$(rel "$BUNDLE")" "/repo/$(rel "$BINARY")" >/dev/null \
        || die "the binary does not verify against its keyless bundle for the expected identity"
    echo "    verified  $(sha256sum "$BINARY" | cut -d' ' -f1)"
else
    log "4/4  no binary given; skipped"
fi

cat <<EOT

KEYLESS VERIFIED

  image   $REF
  source  $COMMIT

This checks that the pipeline identity signed the digest and that Rekor
recorded it. It is not the durable release signature; ci/verify-release.sh
checks that one against the key inventory.
EOT
