#!/usr/bin/env bash
#
# Verify everything a pipeline run signed, from a job that holds no key
# material (Phase 5.9).
#
#   ci/verify-run-artifacts.sh <keys-dir> <binary> <bundle> <image-digest-ref>
#
# # What this proves, and what it does not
#
# It does NOT establish custody. The inventory it reads was signed by the
# same run that made the signatures, so that link is self-consistent by
# construction -- an ephemeral trust root cannot vouch for itself to anybody
# else, and this script never claims it does. `ci/verify-release.sh` is the
# one anchored outside the tree, and it is what a consumer runs.
#
# What it does prove is the thing a signer cannot prove about itself: that
# the signatures are checkable by something that did not make them. This
# runs with no token, no PIN and no module -- so if the signing step had
# produced a signature only the signing environment could verify (a wrong
# key published, a bundle naming a different digest, a format only cosign's
# own writer understands), it fails here. That is why the job is separate
# rather than a second command in the signing one.
#
# Both artifacts are checked, each against the key for its own purpose, and
# the keys come out of the inventory rather than being named here.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

die() { echo "verify-run-artifacts: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# go.mod requires a Go newer than the runner ships, and pinning the toolchain
# matters here for the same reason it does in ci/scan-deps.sh: the verifier
# should be built by the toolchain that builds the thing being verified, not
# by whatever the CI image happens to carry this month. Read out of the
# service Dockerfile rather than copied from it, so a builder bump moves this
# with it instead of leaving a second copy to drift.
GO_IMAGE="$(buildGoImage "${REPO_ROOT}/deploy/docker/Dockerfile")"

# Everything the verifier touches has to be inside the repository, because
# that is the only thing mounted into the container. A path outside it would
# resolve against the container's own filesystem -- which does not fail, it
# reads a different file, and that is the dangerous kind of wrong
# (ci/sign-artifact.sh's header records the measurement).
in_repo() {
    case "$(realpath -m -- "$1")" in
        "$REPO_ROOT"/*) return 0 ;;
        *) return 1 ;;
    esac
}
rel() { realpath --relative-to="$REPO_ROOT" -- "$1"; }

# go run, in the pinned toolchain, against paths named from inside.
go_verify() {
    docker run --rm -v "$REPO_ROOT":/repo -w /repo -e GOFLAGS=-mod=readonly \
        "$GO_IMAGE" sh -c "
            git config --global --add safe.directory /repo
            go run ./ci/verify-artifact -key '$1' -bundle '$2' '$3'"
}

KEYS_DIR="${1:?usage: ci/verify-run-artifacts.sh <keys-dir> <binary> <bundle> <image-digest-ref>}"
BINARY="${2:?missing binary}"
BUNDLE="${3:?missing bundle}"
IMAGE_REF="${4:?missing image digest reference}"

# Holding no key material is the whole point of this job, so it is asserted
# rather than assumed -- and the assertion has to be about what the verifying
# *container* can reach, not about what the host happens to have. Both
# verifiers below mount the repository, so a token store anywhere inside it
# is reachable from inside them even though nothing points at it.
#
# In CI this never fires: the verify job is a fresh checkout that downloads
# only public keys and the binary. It fires for a maintainer whose working
# copy still holds the tokens they provisioned, which is a real difference
# worth being told about rather than silently ignoring -- so it is an
# override with a name that says what is being given up, not a bypass.
[ -z "${COSIGN_PKCS11_PIN:-}" ] || die \
    "COSIGN_PKCS11_PIN is set. This job must hold no PIN: a verifier that
could sign proves nothing about the signer."

if [ -z "${HSM_PKI_VERIFY_ACCEPT_REACHABLE_TOKENS:-}" ]; then
    for forbidden in "$REPO_ROOT/.local/ci-signing" "$REPO_ROOT/.local/signing"; do
        [ -d "$forbidden" ] && die \
            "a signing token store is reachable at $forbidden.
Both verifiers below mount the whole repository, so that store is visible
from inside them. In CI this cannot happen -- the verify job is a fresh
checkout holding only public keys. On a machine that has provisioned keys it
can, and then this run demonstrates less than it appears to.

Run it from a clean checkout, or acknowledge the weaker claim explicitly:

    HSM_PKI_VERIFY_ACCEPT_REACHABLE_TOKENS=1 $0 ..."
    done
else
    echo "verify-run-artifacts: WARNING -- a signing token store is reachable" >&2
    echo "  from the verifying containers. This run shows the signatures are" >&2
    echo "  checkable; it does not show the checker could not have signed." >&2
fi

case "$IMAGE_REF" in
    *@sha256:*) ;;
    *) die "image reference must be a digest, not a tag: $IMAGE_REF" ;;
esac

# Normalised before anything else uses them. Everything below strips
# $REPO_ROOT off these paths to name them from inside the container, and a
# relative argument would make that strip a no-op -- which happens to work
# when the caller's cwd is the repository root and silently addresses the
# wrong file when it is not.
KEYS_DIR="$(realpath -m -- "$KEYS_DIR")"
BINARY="$(realpath -m -- "$BINARY")"
BUNDLE="$(realpath -m -- "$BUNDLE")"

for path in "$KEYS_DIR" "$BINARY" "$BUNDLE"; do
    in_repo "$path" || die \
        "$path is outside the repository at $REPO_ROOT.
The verifier runs in a container with only the repository mounted, so a path
outside it silently resolves against the container's filesystem and a
different file gets checked."
done

INVENTORY="$KEYS_DIR/key-inventory.json"
[ -f "$INVENTORY" ] || die "no inventory at $INVENTORY"

log "1/5  the run's inventory is internally consistent (NOT a custody claim)"
openssl dgst -sha256 -verify "$KEYS_DIR/inventory-signing-key-v1.pub" \
    -signature "$KEYS_DIR/key-inventory.json.sig" "$INVENTORY" \
    || die "the run's own inventory does not verify against the run's own
inventory key. That is a broken pipeline, not a trust problem."
echo "    (ephemeral trust root: this says the run agrees with itself)"

# Keys by purpose, out of the inventory. Naming them here would defeat 3.7
# and would also hide a rotation bug: if the pipeline signed with a key the
# inventory does not list, that must fail, and hardcoding the key it used
# would make it pass.
key_for() {
    python3 - "$INVENTORY" "$KEYS_DIR" "$1" <<'PY'
import json, sys, os
inv = json.load(open(sys.argv[1]))
for k in inv.get("keys", []):
    if k.get("purpose") == sys.argv[3] and k.get("status") in ("active", "verify-only"):
        p = os.path.join(sys.argv[2], k["label"] + ".pub")
        if not os.path.exists(p):
            open(p, "w").write(k["public_key"])
        print(p)
        break
PY
}

ARTIFACT_KEY="$(key_for artifact)"
IMAGE_KEY="$(key_for image)"
[ -n "$ARTIFACT_KEY" ] || die "the inventory lists no usable artifact-signing key"
[ -n "$IMAGE_KEY" ] || die "the inventory lists no usable image-signing key"

log "2/5  the release binary, checked by the Go standard library"
# ci/verify-artifact re-derives the answer from crypto/ecdsa rather than
# asking cosign whether cosign was right.
go_verify "$(rel "$ARTIFACT_KEY")" "$(rel "$BUNDLE")" "$(rel "$BINARY")" \
    || die "the release binary does not verify against the artifact key the
run published. The signature is not checkable outside the signer."

log "3/5  the image, checked with no token mounted"
export HSM_PKI_COSIGN_VERSION=v2
"$REPO_ROOT/ci/cosign.sh" fetch >/dev/null
rel_image_key="${IMAGE_KEY#"$REPO_ROOT"/}"
HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" verify \
    --key "/repo/$rel_image_key" --insecure-ignore-tlog=true \
    "$IMAGE_REF" >/dev/null \
    || die "the image signature does not verify against the image key the run
published."
echo "    verified"

# --- the negative half -------------------------------------------------
# A verifier that has only ever been shown valid input is indistinguishable
# from one that returns success unconditionally. Both refusals below are
# asserted on every run, so the day one of them stops refusing, this job goes
# red rather than quietly approving.

log "4/5  a tampered binary must be refused"
TAMPER_DIR="$REPO_ROOT/.local/verify-negative"
mkdir -p "$TAMPER_DIR"
TAMPERED="$TAMPER_DIR/hsm-pki-server"
cp "$BINARY" "$TAMPERED"
# One byte appended: the smallest change that still changes the digest, and a
# realistic one -- a truncated or padded download looks exactly like this.
printf '\0' >> "$TAMPERED"
if go_verify "$(rel "$ARTIFACT_KEY")" "$(rel "$BUNDLE")" "$(rel "$TAMPERED")" >/dev/null 2>&1; then
    die "a tampered binary VERIFIED. The gate is not a gate."
fi
echo "    refused"

log "5/5  the wrong purpose's key must be refused"
# CLAUDE.md 3.6 says the keys are purpose-separated and never interchangeable.
# That is a claim about behaviour, so it is measured: the image key must not
# validate a release artifact.
if go_verify "$(rel "$IMAGE_KEY")" "$(rel "$BUNDLE")" "$(rel "$BINARY")" >/dev/null 2>&1; then
    die "the IMAGE key verified a release artifact. Purpose separation is
not being enforced by anything, whatever the labels say."
fi
echo "    refused"

cat <<EOF

All signatures made by this run are checkable by something that did not make
them, and all three negative cases are refused.

  binary  $(sha256sum "$BINARY" | cut -d' ' -f1)
  image   $IMAGE_REF

This is a mechanism result, not a custody one: the trust root was created by
the same run. ci/verify-release.sh is the anchored check a consumer runs.
EOF
