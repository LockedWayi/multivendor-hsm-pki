#!/usr/bin/env bash
#
# Counter-sign a published image with the durable key, so that somebody who
# does not trust this repository can verify it (Phase 5.9).
#
#   ci/countersign-release.sh ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:<digest>
#
# # Why this is a separate, manual step and not part of the pipeline
#
# The pipeline signs every published image, but with keys it provisions for
# the run and destroys with the runner. That proves the signing mechanism
# end to end over a real PKCS#11 token, and it proves nothing about custody:
# the key came from the same build that produced the artifact, so a consumer
# checking it learns only that the build agreed with itself.
#
# A signature that means something to a stranger has to be made by a key
# whose authority does not come from the thing being signed. That key is
# image-signing-key-v1 on the maintainer's own token -- listed in the
# inventory, which is signed by an offline token, whose public half lives in
# a separate repository. CI cannot have that key without either committing
# key material or exposing the development machine to pipeline execution,
# and both were rejected with reasons (phase 5.9).
#
# So the durable signature is applied deliberately, by a person, to the
# digests that are meant to be consumed. That is not a workaround for a
# missing feature; it is what an offline-ish signing key is for. Ordinary
# `main` builds stay development artifacts, and the README says so.
#
# # Where the durable token actually is
#
# HSM_PKI_SIGNING_STATE defaults to .local/signing inside this checkout, which
# is right for whoever provisioned the keys here. It is worth saying out loud
# that a fresh clone has no such directory -- the token is wherever
# deploy/docker/provision-signing-keys.sh was first run, which is not
# necessarily this working copy:
#
#   HSM_PKI_SIGNING_STATE=/path/to/that/checkout/.local/signing \
#   COSIGN_PKCS11_PIN=... ci/countersign-release.sh <digest>
#
# Getting this wrong fails closed rather than quietly: ci/cosign.sh refuses
# a missing store by name instead of inventing one, and the key check below
# refuses a keys directory that is not docs/keys.
#
# # What "done" means here
#
# Not "cosign exited 0". This script's success criterion is that
# ci/verify-release.sh -- the verification a stranger runs, anchored outside
# this tree -- passes afterwards and failed before. A signature nobody else
# can check is the thing this exists to stop producing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "countersign-release: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

REF="${1:-}"
[ -n "$REF" ] || die "usage: ci/countersign-release.sh <image-reference>@sha256:<digest>"

case "$REF" in
    *@sha256:*) ;;
    *) die "refusing to sign a tag: $REF
A signature is made over a digest. Signing whatever a name points at right
now attests to nothing that survives the next push (CLAUDE.md 3.8)." ;;
esac

[ -n "${COSIGN_PKCS11_PIN:-}" ] || die \
    "set COSIGN_PKCS11_PIN. The PIN reaches cosign as an environment
variable and never inside a PKCS#11 URI (CLAUDE.md 3.1)."

# Writing a signature is a registry PUSH, so cosign needs the operator's
# credentials -- and it runs in a container that mounts only what it is told
# to. Left unset, cosign is silently anonymous and the push fails with an
# authentication error from a step whose subject is signing, which sends the
# reader to the key and the token. Defaulted here to the place `docker login`
# actually writes, so the ordinary case works without anybody having to know
# this paragraph exists.
if [ -z "${HSM_PKI_DOCKER_CONFIG:-}" ] && [ -d "$HOME/.docker" ]; then
    export HSM_PKI_DOCKER_CONFIG="$HOME/.docker"
fi
[ -n "${HSM_PKI_DOCKER_CONFIG:-}" ] || die \
    "no registry credentials to sign with.
Counter-signing pushes a signature to the registry, so it needs a login:

    docker login ghcr.io -u <you>       # a token with write:packages

Then re-run. (Or point HSM_PKI_DOCKER_CONFIG at a directory holding a
config.json, which is what DOCKER_CONFIG names.)"

# The durable state, explicitly. Defaulting to it would be enough, but this
# script must never silently counter-sign with whatever token happens to be
# configured -- pointing HSM_PKI_SIGNING_STATE at a CI store and getting a
# "successful" counter-signature from an ephemeral key is exactly the
# confusion this whole step exists to remove.
STATE="${HSM_PKI_SIGNING_STATE:-$REPO_ROOT/.local/signing}"
KEYS_DIR="${HSM_PKI_KEYS_DIR:-$REPO_ROOT/docs/keys}"
[ "$KEYS_DIR" = "$REPO_ROOT/docs/keys" ] || die \
    "refusing to counter-sign with keys from $KEYS_DIR.
The durable signature must be made by the key the published inventory lists,
which is the one in docs/keys. If you are testing the mechanism, use
ci/publish-image.sh's ephemeral path instead."

log "checking the chain BEFORE counter-signing"
# Establishes the negative. A script that only ever runs its check after the
# change cannot tell a working signature from a check that always passes.
if "$REPO_ROOT/ci/verify-release.sh" "$REF" >/dev/null 2>&1; then
    echo "    already verifiable -- this digest is counter-signed already."
    echo "    Nothing to do."
    exit 0
fi
echo "    not verifiable yet, as expected"

log "counter-signing with the durable key on $STATE"
# ci/sign-image.sh defaults plaintext to ALLOWED, which dates from the local
# k3d registry. A release counter-signature must not inherit that: stated
# here so the safe value is the one nobody has to remember.
HSM_PKI_SIGNING_STATE="$STATE" HSM_PKI_KEYS_DIR="$KEYS_DIR" \
HSM_PKI_REGISTRY_ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-false}" \
    "$REPO_ROOT/ci/sign-image.sh" "$REF"

log "checking the chain AFTER counter-signing"
# The real gate. If this fails the signature exists but is useless to
# everyone except us, which is worse than no signature: it looks protected.
"$REPO_ROOT/ci/verify-release.sh" "$REF" || die \
    "counter-signed, but the independent verification still fails.
The signature exists and nobody else can act on it. Investigate before
announcing this digest as a release."

cat <<EOF

This digest is now verifiable by anyone, with no secret of ours:

  ci/verify-release.sh $REF

or by hand, which is the version worth reading once:

  curl -fsSL https://raw.githubusercontent.com/$(sed -n 's/^TRUST_ANCHOR_REPO="\(.*\)"$/\1/p' "$REPO_ROOT/ci/scanner-pins.sh")/$(sed -n 's/^TRUST_ANCHOR_COMMIT="\(.*\)"$/\1/p' "$REPO_ROOT/ci/scanner-pins.sh")/inventory-signing-key-v1.pub -o anchor.pub
  openssl dgst -sha256 -verify anchor.pub \\
      -signature docs/keys/key-inventory.json.sig docs/keys/key-inventory.json
  # then verify the image with the image key listed in that inventory
EOF
