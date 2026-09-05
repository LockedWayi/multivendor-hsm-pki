#!/usr/bin/env bash
#
# Verify a published image the way somebody who does not trust this
# repository has to (Phase 5.9).
#
#   ci/verify-release.sh ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:<digest>
#
# # The question this answers
#
# "The maintainer published a key and a signature, and the signature checks
# out against the key" is worth nothing on its own. Whoever can write to this
# repository can replace the inventory, its signature and the public key that
# verifies it in one commit, and the check still passes -- it proves the three
# files agree with each other. That is the self-consistency failure
# CLAUDE.md 3.10 names, and it is the reason a verification recipe pointing
# at docs/keys/ alone is theatre.
#
# What makes this different is where step 1 gets its anchor. The key that
# signs the inventory lives in a *separate, separately protected* repository
# (LockedWayi/hsm-pki-trust-anchor), pinned here by commit and by content
# digest, and its private half is on an offline token that no pipeline can
# reach. So forging the chain below needs a compromise of two repositories
# and a token that is in neither of them -- not one push.
#
# # The chain, and why each link is where it is
#
#   1. anchor        fetched from the other repository, pinned twice.
#                    Fails closed: an unreachable anchor NEVER falls back
#                    to the copy in this tree, because that copy is exactly
#                    what this script exists to stop trusting.
#   2. inventory     verified against the anchor with openssl -- an
#                    implementation that is not this repository's code and
#                    did not produce the signature (CLAUDE.md 3.10).
#   3. the key       taken FROM the verified inventory, never hardcoded.
#                    That is what makes rotation work: a signature made by
#                    a previous version still verifies while that version
#                    is listed verify-only (CLAUDE.md 3.7).
#   4. the image     verified by digest, with no token mounted anywhere.
#
# Every step is a refusal on failure. There is no partial success.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$REPO_ROOT/.local/verify"

die() { echo "verify-release: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# --inventory-only checks links 1-3 and stops: the anchor is reachable, the
# inventory verifies against it, and it names at least one usable image key.
#
# That is the half CI can assert on every push. The image half cannot be:
# an ordinary `main` build carries only the pipeline's ephemeral signature
# by design, so requiring a release signature on every commit would make
# this gate red for the normal case -- and a gate that is red normally is a
# gate people learn to ignore.
#
# What it still catches is the attack the anchor exists for: anybody
# rewriting docs/keys/ in this tree fails link 2, because the key that
# would have to re-sign the inventory is on an offline token in another
# repository.
INVENTORY_ONLY=0
if [ "${1:-}" = "--inventory-only" ]; then
    INVENTORY_ONLY=1
    shift
fi

REF="${1:-}"
if [ "$INVENTORY_ONLY" = "1" ]; then
    REF="(inventory only)"
else
    [ -n "$REF" ] || die "usage: ci/verify-release.sh [--inventory-only] <image-reference>@sha256:<digest>"
fi

# A tag is a pointer somebody can move; a digest is the bytes. Verifying
# "whatever this name points at right now" attests to nothing that survives
# the next push, so the tag form is refused rather than resolved -- resolving
# it would silently re-introduce the very indirection being rejected.
case "${INVENTORY_ONLY}${REF}" in
    1*) ;;
    *@sha256:*) ;;
    *) die "refusing to verify a tag: $REF
Pass the digest form. A tag is a pointer somebody can move, so verifying one
says nothing about the bytes anybody else will pull (CLAUDE.md 3.8)." ;;
esac

# Refused unless somebody says otherwise. false is right for every real
# registry; a local one over HTTP is how this script is exercised.
ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-false}"

mkdir -p "$WORK"
ANCHOR="$WORK/anchor.pub"

log "1/4  fetching the trust anchor from outside the tree being verified"
"$REPO_ROOT/ci/fetch-trust-anchor.sh" "$ANCHOR"

log "2/4  verifying the key inventory against that anchor, with openssl"
# openssl, not this repository's Go. A signature checked only by the library
# that produced it proves the code agrees with itself.
INVENTORY="$REPO_ROOT/docs/keys/key-inventory.json"
INVENTORY_SIG="$REPO_ROOT/docs/keys/key-inventory.json.sig"
[ -f "$INVENTORY" ] || die "no inventory at $INVENTORY"
[ -f "$INVENTORY_SIG" ] || die "no inventory signature at $INVENTORY_SIG"

openssl dgst -sha256 -verify "$ANCHOR" \
    -signature "$INVENTORY_SIG" "$INVENTORY" \
    || die "the key inventory does not verify against the out-of-band anchor.
Either this tree's docs/keys/ has been changed without the offline inventory
token, or the pinned anchor is stale. Both are refusals, not warnings."

log "3/4  reading the image-signing keys out of the verified inventory"
# From the inventory, never hardcoded. Retired keys are excluded: a key the
# inventory says is retired must not verify anything, or retirement means
# nothing. verify-only keys ARE accepted -- that state exists precisely so a
# signature made before a rotation keeps verifying during the transition.
mapfile -t KEY_FILES < <(python3 - "$INVENTORY" "$WORK" <<'PY'
import json, sys, os
inventory_path, work = sys.argv[1], sys.argv[2]
inv = json.load(open(inventory_path))
out = []
for k in inv.get("keys", []):
    if k.get("purpose") != "image":
        continue
    if k.get("status") not in ("active", "verify-only"):
        continue
    path = os.path.join(work, k["label"] + ".pub")
    with open(path, "w") as fh:
        fh.write(k["public_key"])
    out.append("%s\t%s\t%s" % (path, k["label"], k["status"]))
print("\n".join(out))
PY
)

[ "${#KEY_FILES[@]}" -gt 0 ] && [ -n "${KEY_FILES[0]}" ] || die \
    "the verified inventory lists no usable image-signing key.
An inventory with nothing to verify against is a refusal, not a pass."

for entry in "${KEY_FILES[@]}"; do
    printf '    %s (%s)\n' "$(cut -f2 <<<"$entry")" "$(cut -f3 <<<"$entry")"
done

if [ "$INVENTORY_ONLY" = "1" ]; then
    cat <<EOF

INVENTORY VERIFIED (links 1-3 of 4)

The anchor was reachable, the inventory verifies against it, and it names a
usable image-signing key. The image half was not checked: pass a digest
instead of --inventory-only to check a specific release.
EOF
    exit 0
fi

log "4/4  verifying the image signature, with no token mounted"
# cosign v2: the layout Kyverno's verifier also reads, so what passes here
# is what admission will accept.
export HSM_PKI_COSIGN_VERSION=v2
"$REPO_ROOT/ci/cosign.sh" fetch >/dev/null

verified=""
for entry in "${KEY_FILES[@]}"; do
    key_path="$(cut -f1 <<<"$entry")"
    label="$(cut -f2 <<<"$entry")"
    rel="${key_path#"$REPO_ROOT"/}"
    if HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" verify \
            --key "/repo/$rel" --insecure-ignore-tlog=true \
            --allow-http-registry="$ALLOW_HTTP" \
            "$REF" >/dev/null 2>&1; then
        verified="$label"
        break
    fi
done

[ -n "$verified" ] || die \
    "no key in the verified inventory produced this signature.

The image is not vouched for by any key this project publishes. If it came
from a pipeline run, that is expected: CI signs with an ephemeral key that
exists only for the length of the build, which proves the signing mechanism
and says nothing about custody. Such an image is deliberately not
deployable -- see the README."

cat <<EOF

VERIFIED

  image      $REF
  signed by  $verified
  listed in  docs/keys/key-inventory.json
  vouched by $(sed -n 's/^TRUST_ANCHOR_REPO="\(.*\)"$/\1/p' "$REPO_ROOT/ci/scanner-pins.sh") @ $(sed -n 's/^TRUST_ANCHOR_COMMIT="\(.*\)"$/\1/p' "$REPO_ROOT/ci/scanner-pins.sh" | cut -c1-12)

Nothing in this chain was taken on the word of this repository alone: the
anchor came from a separately protected repository, the inventory was checked
against it by openssl rather than by code shipped here, and the key was read
out of the inventory rather than hardcoded.
EOF
