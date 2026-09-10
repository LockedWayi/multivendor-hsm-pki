#!/usr/bin/env bash
#
# Verify everything the signing mechanism test signed, with public keys
# only.
#
#   ci/verify-run-artifacts.sh <keys-dir> <binary> <bundle> <image>@sha256:<digest> [<commit>]
#
# The keys in <keys-dir> were provisioned by the same run that made the
# signatures, so this is not a custody check. It checks that the signatures
# are readable by something that did not make them: the binary through
# ci/verify-artifact (Go standard library), the image and its attestations
# through cosign with a public key, and the provenance content through
# ci/check-provenance.sh. Three refusals are asserted as well: a tampered
# binary, the wrong purpose's key, and a provenance statement about the
# wrong subject would each pass a verifier that returns success
# unconditionally.
#
# Keys are selected from the run's inventory by ci/select-key, never named
# here, so a signing key the inventory does not list fails.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

die() { echo "verify-run-artifacts: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

KEYS_DIR="${1:?usage: ci/verify-run-artifacts.sh <keys-dir> <binary> <bundle> <image>@sha256:<digest> [<commit>]}"
BINARY="${2:?missing binary}"
BUNDLE="${3:?missing bundle}"
IMAGE_REF="${4:?missing image digest reference}"
EXPECT_COMMIT="${5:-${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}}"
ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-false}"

# A verifier that holds a PIN could sign. This one must not.
[ -z "${COSIGN_PKCS11_PIN:-}" ] || die "COSIGN_PKCS11_PIN is set. This verifier must hold no PIN."

case "$IMAGE_REF" in
    *@sha256:*) ;;
    *) die "image reference must be a digest, not a tag: $IMAGE_REF" ;;
esac

# Everything the verifier reads is inside the repository, because that is
# the only thing mounted into the containers.
rel() {
    local resolved
    resolved="$(realpath -m -- "$1")"
    case "$resolved" in
        "$REPO_ROOT"/*) printf '%s' "${resolved#"$REPO_ROOT"/}" ;;
        *) die "$1 is outside the repository at $REPO_ROOT. The verifiers run in containers that mount only the repository." ;;
    esac
}
KEYS_REL="$(rel "$KEYS_DIR")"
BINARY_REL="$(rel "$BINARY")"
BUNDLE_REL="$(rel "$BUNDLE")"
INVENTORY="$REPO_ROOT/$KEYS_REL/key-inventory.json"
[ -f "$INVENTORY" ] || die "no inventory at $INVENTORY"

# Created host-side before any container writes into it, so the next run
# can empty it.
WORK="$REPO_ROOT/.local/verify-run"
rm -rf "$WORK"
mkdir -p "$WORK/keys"
WORK_REL="${WORK#"$REPO_ROOT"/}"

log "1/7  the run's inventory verifies against the run's own inventory key"
openssl dgst -sha256 -verify "$REPO_ROOT/$KEYS_REL/inventory-signing-key-v1.pub" \
    -signature "$REPO_ROOT/$KEYS_REL/key-inventory.json.sig" "$INVENTORY" \
    || die "the run's inventory does not verify against the run's inventory key. That is a broken pipeline."
echo "    (same run made both; this is not a custody claim)"

log "2/7  selecting the keys from the inventory"
select_key() {   # select_key <purpose>: prints the repo-relative PEM path of the first usable key
    local line
    line="$(goRun ./ci/select-key -inventory "/repo/$KEYS_REL/key-inventory.json" \
        -purpose "$1" -out-dir "/repo/$WORK_REL/keys" | head -1)" || return 1
    [ -n "$line" ] || return 1
    printf '%s' "$(cut -f3 <<<"$line" | sed 's|^/repo/||')"
}
ARTIFACT_KEY="$(select_key artifact)" || die "the inventory lists no usable artifact-signing key"
IMAGE_KEY="$(select_key image)" || die "the inventory lists no usable image-signing key"
echo "    artifact  $ARTIFACT_KEY"
echo "    image     $IMAGE_KEY"

go_verify() {   # go_verify <key rel> <bundle rel> <artifact rel>
    goRun ./ci/verify-artifact -key "/repo/$1" -bundle "/repo/$2" "/repo/$3"
}

log "3/7  the release binary, checked by the Go standard library"
go_verify "$ARTIFACT_KEY" "$BUNDLE_REL" "$BINARY_REL" \
    || die "the binary does not verify against the artifact key the run published."

log "4/7  the image signature and both attestations, with no token mounted"
export HSM_PKI_COSIGN_VERSION=v2
"$REPO_ROOT/ci/cosign.sh" fetch >/dev/null
cosign_verify() {   # cosign_verify <subcommand> [args]
    HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" "$@" \
        --key "/repo/$IMAGE_KEY" --insecure-ignore-tlog=true \
        --allow-http-registry="$ALLOW_HTTP" "$IMAGE_REF"
}
cosign_verify verify >/dev/null 2>&1 \
    || die "the image signature does not verify against the image key the run published."
echo "    signature      verified"
cosign_verify verify-attestation --type cyclonedx >/dev/null 2>&1 \
    || die "the CycloneDX SBOM attestation does not verify against the image key."
echo "    SBOM           verified"
PROVENANCE="$WORK/provenance.dsse.json"
cosign_verify verify-attestation --type slsaprovenance1 > "$PROVENANCE" 2>/dev/null \
    || die "the SLSA provenance attestation does not verify against the image key."
echo "    provenance     verified"

log "5/7  the provenance says what it should"
"$REPO_ROOT/ci/check-provenance.sh" "$PROVENANCE" "${IMAGE_REF#*@}" "$EXPECT_COMMIT"

log "6/7  a tampered binary must be refused"
TAMPERED="$WORK/hsm-pki-server"
cp "$BINARY" "$TAMPERED"
printf '\0' >> "$TAMPERED"
if go_verify "$ARTIFACT_KEY" "$BUNDLE_REL" "$WORK_REL/hsm-pki-server" >/dev/null 2>&1; then
    die "a tampered binary VERIFIED."
fi
echo "    refused"

log "7/7  the wrong purpose's key must be refused"
if go_verify "$IMAGE_KEY" "$BUNDLE_REL" "$BINARY_REL" >/dev/null 2>&1; then
    die "the image key verified a release artifact. Purpose separation is not enforced."
fi
echo "    refused"

cat <<EOT

Every signature the mechanism test made is checkable with public keys only,
the provenance says what it should, and the refusals hold.

  binary  $(sha256sum "$BINARY" | cut -d' ' -f1)
  image   $IMAGE_REF
EOT
