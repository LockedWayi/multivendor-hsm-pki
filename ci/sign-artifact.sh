#!/usr/bin/env bash
#
# Sign a release artifact with the artifact-signing key over PKCS#11, and
# refuse to leave a bundle an independent verifier does not accept.
#
#   ci/sign-artifact.sh <artifact> [output-bundle]
#
# The key signs release artifacts and nothing else. Images are signed by
# image-signing-key-v1 and certificates by the CA.
#
# No transparency log for this key. cosign v3 defaults to a signing config
# from TUF, which uploads to the public Rekor instance and prompts. Neither
# --tlog-upload=false nor --use-signing-config=false avoids that; a signing
# config declaring no log service does, and that is
# ci/cosign-signing-config.json. Measured on v3.1.3. The key is long-lived
# and published in a signed inventory, so a log entry would add nothing to
# the trust decision.
#
# ci/verify-artifact re-derives the answer from the Go standard library,
# and the bundle is deleted if it disagrees.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"
KEY_LABEL="artifact-signing-key-v1"
TOKEN_LABEL="${HSM_PKI_SUPPLY_TOKEN:-hsm-pki-local-supply-chain}"
# The published public key, named relative to the repository because the
# signing container mounts it at /repo. Overridable for the mechanism test.
KEYS_DIR="${HSM_PKI_KEYS_DIR:-$REPO_ROOT/docs/keys}"
case "$KEYS_DIR" in
    "$REPO_ROOT"/*) PUBLIC_KEY="${KEYS_DIR#"$REPO_ROOT"/}/$KEY_LABEL.pub" ;;
    *)
        echo "sign-artifact: HSM_PKI_KEYS_DIR must be inside $REPO_ROOT --" >&2
        echo "the signing container mounts only the repository, so a path" >&2
        echo "outside it resolves against the container's own filesystem." >&2
        exit 1 ;;
esac

die() { echo "sign-artifact: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

ARTIFACT="${1:-}"
[ -n "$ARTIFACT" ] || die "usage: ci/sign-artifact.sh <artifact> [output-bundle]"
[ -f "$ARTIFACT" ] || die "no such artifact: $ARTIFACT"
BUNDLE="${2:-$ARTIFACT.bundle}"

[ -n "${COSIGN_PKCS11_PIN:-}" ] || die \
    "set COSIGN_PKCS11_PIN. The PIN reaches cosign as an environment
variable and never as pin-value= in the PKCS#11 URI -- a URI is a command
line argument, so it reaches ps output, shell history and any log that
echoes the command."

# The container mounts the repository at /repo and nothing else. A path
# outside it resolves against the container's own filesystem: signing
# /etc/hostname once hashed and signed the container's /etc/hostname,
# correctly, under the right key. ci/verify-artifact refused the bundle,
# and the message named the symptom, so the containment is checked here.
inside_repo() {
    local resolved
    resolved="$(realpath -m -- "$1")"
    case "$resolved" in
        "$REPO_ROOT"/*) return 0 ;;
        *) return 1 ;;
    esac
}

rel() { realpath --relative-to="$REPO_ROOT" -- "$1"; }

for path in "$ARTIFACT" "$BUNDLE"; do
    inside_repo "$path" || die \
        "$path is outside the repository at $REPO_ROOT.
The signer runs in a container with only the repository mounted, so a path
outside it resolves against the container's own filesystem -- which means
signing whatever happens to be at that path in the container, or writing a
bundle the host never receives. Copy the artifact into the repository (or
into .local/) and sign it there."
done

# --signing-config exists only in cosign v3. Under v2 it is ignored, cosign
# falls through to the public Rekor instance, and the only thing between
# that and a published record is an interactive prompt, which hangs a
# container with no stdin. So the version is asserted.
COSIGN_TRACK="${HSM_PKI_COSIGN_VERSION:-v3}"
[ "$COSIGN_TRACK" = "v3" ] || die \
    "refusing to sign under cosign $COSIGN_TRACK.

Release artifacts are signed with v3 because --signing-config, which is how
this script declares 'no transparency log', exists only there. Under $COSIGN_TRACK
that flag is ignored and cosign uploads to the public Rekor instance
instead.

Unset HSM_PKI_COSIGN_VERSION, or set it to v3."

log "signing $(rel "$ARTIFACT") with $KEY_LABEL on token $TOKEN_LABEL"
"$REPO_ROOT/ci/cosign.sh" sign-blob \
    --key "pkcs11:token=$TOKEN_LABEL;object=$KEY_LABEL" \
    --signing-config "/repo/ci/cosign-signing-config.json" \
    --bundle "/repo/$(rel "$BUNDLE")" \
    "/repo/$(rel "$ARTIFACT")"

# cosign runs as root in the container, because SoftHSM2's token
# directories are 0700 and owned by the user that initialised them, also
# root. The bundle lands root-owned and 0600, unreadable to the verifier
# below.
docker run --rm -v "$(cd "$(dirname "$BUNDLE")" && pwd)":/out "$ALPINE_IMAGE" \
    chown "$(id -u):$(id -g)" "/out/$(basename "$BUNDLE")"
chmod 0644 "$BUNDLE"

log "verifying it with an implementation that is not cosign"
if ! go run "$REPO_ROOT/ci/verify-artifact" \
        -key "$REPO_ROOT/$PUBLIC_KEY" \
        -bundle "$BUNDLE" "$ARTIFACT"; then
    rm -f "$BUNDLE"
    die "the signature did not verify. The bundle has been removed rather
than left beside the artifact."
fi

cat <<EOF

Signed. Anyone holding the artifact, the bundle and the published public key
can check it without an HSM, a PIN, or this repository:

  go run ./ci/verify-artifact -key $PUBLIC_KEY \\
      -bundle $(rel "$BUNDLE") $(rel "$ARTIFACT")

or with cosign, which needs --insecure-ignore-tlog because its default
trust model expects a transparency log entry that a key-based signature
does not have:

  cosign verify-blob --key $PUBLIC_KEY --insecure-ignore-tlog=true \\
      --bundle $(rel "$BUNDLE") $(rel "$ARTIFACT")

The key is listed, with its purpose and lifecycle state, in the signed
inventory at docs/keys/key-inventory.json. Check that first, with openssl:

  openssl dgst -sha256 -verify docs/keys/inventory-signing-key-v1.pub \\
      -signature docs/keys/key-inventory.json.sig docs/keys/key-inventory.json
EOF
