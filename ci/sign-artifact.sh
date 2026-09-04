#!/usr/bin/env bash
#
# Sign a release artifact over the HSM, then refuse to emit the signature
# unless an independent verifier agrees with it (Phase 4.9).
#
#   ci/sign-artifact.sh <artifact> [output-bundle]
#
# The signing key is artifact-signing-key-v1 on the supply-chain token, and
# it signs release artifacts and nothing else -- images are signed by
# image-signing-key-v1 and certificates by the CA, because a compromise of
# one must not be able to do the others' job (CLAUDE.md §3.6).
#
# # Two things here are decisions rather than mechanics
#
# **No transparency log, established empirically rather than from the docs.**
# cosign v3 defaults --use-signing-config to true and fetches service URLs
# from TUF, so the default path uploads to the public Rekor instance and
# prompts with a notice that the submission is an immutable public record.
# --tlog-upload=false, which used to turn that off, is now refused outright
# in combination with the default (cosign says so itself and points at the
# replacement). --use-signing-config=false does NOT avoid it either: it
# still attempts the upload. What works is a signing config declaring no
# transparency log service, which is what ci/cosign-signing-config.json is.
# Measured, all three, on v3.1.3.
#
# That is the right answer for this platform and not only the working one.
# Rekor exists to bound the validity of an *ephemeral* Fulcio certificate in
# time. This platform signs with a long-lived key whose public half is
# published in a signed inventory, so a log entry would add a public record
# of every internal release without adding anything to the trust decision.
#
# **The gate is the independent verifier, not cosign.** cosign verifying its
# own output proves cosign agrees with itself -- the closed loop that shipped
# an unreadable CRL here once (docs/lessons.md §2, CLAUDE.md §3.10). So
# ci/verify-artifact re-derives the answer from the Go standard library, and
# the bundle is deleted if it disagrees: a signature that has not been
# checked must not be distinguishable, on disk, from one that has.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_LABEL="artifact-signing-key-v1"
TOKEN_LABEL="${HSM_PKI_SUPPLY_TOKEN:-hsm-pki-local-supply-chain}"
PUBLIC_KEY="docs/keys/$KEY_LABEL.pub"

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
echoes the command (CLAUDE.md §3.1)."

# Paths as the runner sees them: ci/cosign.sh mounts the repository at /repo.
rel() { realpath --relative-to="$REPO_ROOT" "$1"; }

log "signing $(rel "$ARTIFACT") with $KEY_LABEL on token $TOKEN_LABEL"
"$REPO_ROOT/ci/cosign.sh" sign-blob \
    --key "pkcs11:token=$TOKEN_LABEL;object=$KEY_LABEL" \
    --signing-config "/repo/ci/cosign-signing-config.json" \
    --bundle "/repo/$(rel "$BUNDLE")" \
    "/repo/$(rel "$ARTIFACT")"

# cosign runs as root in the runner, because SoftHSM2's token directories
# are 0700 owned by the user that initialised them -- also root, in a
# container. So the bundle lands root-owned and 0600, unreadable to the
# operator who asked for it and to the verifier below, which is a failure
# that looks exactly like a bad signature. Handed back here rather than left
# for the reader to discover.
docker run --rm -v "$(cd "$(dirname "$BUNDLE")" && pwd)":/out alpine:3 \
    chown "$(id -u):$(id -g)" "/out/$(basename "$BUNDLE")"
chmod 0644 "$BUNDLE"

log "verifying it with an implementation that is not cosign"
if ! go run "$REPO_ROOT/ci/verify-artifact" \
        -key "$REPO_ROOT/$PUBLIC_KEY" \
        -bundle "$BUNDLE" "$ARTIFACT"; then
    rm -f "$BUNDLE"
    die "the signature did not verify. The bundle has been removed rather
than left beside the artifact, because an unverified signature that looks
like a verified one is worse than none (CLAUDE.md §3.4)."
fi

cat <<EOF

Signed. Anyone holding the artifact, the bundle and the published public key
can check it without an HSM, a PIN, or this repository:

  go run ./ci/verify-artifact -key $PUBLIC_KEY \\
      -bundle $(rel "$BUNDLE") $(rel "$ARTIFACT")

or with cosign, which needs --insecure-ignore-tlog because its default trust
model expects a transparency log entry that a key-based signature does not
have -- the warning it prints is about that default, not about this
signature:

  cosign verify-blob --key $PUBLIC_KEY --insecure-ignore-tlog=true \\
      --bundle $(rel "$BUNDLE") $(rel "$ARTIFACT")

The key itself is listed, with its purpose and lifecycle state, in the signed
inventory at docs/keys/key-inventory.json -- check that first, with openssl
and nothing else:

  openssl dgst -sha256 -verify docs/keys/inventory-signing-key-v1.pub \\
      -signature docs/keys/key-inventory.json.sig docs/keys/key-inventory.json
EOF
