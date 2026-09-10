#!/usr/bin/env bash
#
# Fetch the key-inventory trust anchor from the repository that publishes
# it, and refuse to produce anything else.
#
#   ci/fetch-trust-anchor.sh <output-path>
#
# The anchor's location is not read from any file in this tree. The tree is
# the thing being verified, so a pin inside it belongs to whoever can write
# here. The caller supplies three values from outside:
#
#   HSM_PKI_TRUST_ANCHOR_REPO     owner/name of the anchor repository
#   HSM_PKI_TRUST_ANCHOR_COMMIT   the commit to read the file at, 40 hex
#   HSM_PKI_TRUST_ANCHOR_SHA256   the SHA-256 of the file's exact bytes
#
# In CI they come from GitHub repository variables. A consumer sets them by
# hand. A consumer who copies them from this repository's README trusts
# this repository for that step. The values have to come from somewhere
# the consumer trusts more than this tree.
#
# Optional:
#   HSM_PKI_TRUST_ANCHOR_FILE      file name, default inventory-signing-key-v1.pub
#   HSM_PKI_TRUST_ANCHOR_BASE_URL  default https://raw.githubusercontent.com.
#                                  ci/signing-mechanism-test.sh points it at
#                                  a local server. Nothing else should.
#
# The commit pin fixes the content. The digest pin is the check that still
# holds when the transport or the host substitutes a response.
set -euo pipefail

die() { echo "fetch-trust-anchor: $*" >&2; exit 1; }

OUT="${1:-}"
REPO="${HSM_PKI_TRUST_ANCHOR_REPO:-}"
COMMIT="${HSM_PKI_TRUST_ANCHOR_COMMIT:-}"
SHA256="${HSM_PKI_TRUST_ANCHOR_SHA256:-}"
FILE="${HSM_PKI_TRUST_ANCHOR_FILE:-inventory-signing-key-v1.pub}"
BASE_URL="${HSM_PKI_TRUST_ANCHOR_BASE_URL:-https://raw.githubusercontent.com}"

if [ -z "$OUT" ] || [ -z "$REPO" ] || [ -z "$COMMIT" ] || [ -z "$SHA256" ]; then
    cat >&2 <<'USAGE'
usage: HSM_PKI_TRUST_ANCHOR_REPO=<owner/name> \
       HSM_PKI_TRUST_ANCHOR_COMMIT=<40-hex commit> \
       HSM_PKI_TRUST_ANCHOR_SHA256=<64-hex digest of the anchor file> \
       ci/fetch-trust-anchor.sh <output-path>

The anchor inputs are not read from this tree. Supply them from a source
you trust more than this repository.
USAGE
    exit 2
fi

case "$REPO" in
    */*) ;;
    *) die "HSM_PKI_TRUST_ANCHOR_REPO must be owner/name, got $REPO" ;;
esac
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "HSM_PKI_TRUST_ANCHOR_COMMIT must be a 40-hex commit, got $COMMIT"
[[ "$SHA256" =~ ^[0-9a-f]{64}$ ]] || die "HSM_PKI_TRUST_ANCHOR_SHA256 must be a 64-hex digest, got $SHA256"

URL="$BASE_URL/$REPO/$COMMIT/$FILE"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "==> fetching the trust anchor"
echo "    $REPO @ $COMMIT"
# --fail: an HTTP error page must not be written to the output file.
if ! curl -fsSL --max-time 30 --retry 2 "$URL" -o "$TMP"; then
    echo "fetch-trust-anchor: could not fetch the anchor from $URL" >&2
    echo "  Refusing to continue. Do not substitute docs/keys/: an anchor" >&2
    echo "  taken from the tree under verification proves nothing." >&2
    exit 1
fi

GOT="$(sha256sum "$TMP" | cut -d' ' -f1)"
if [ "$GOT" != "$SHA256" ]; then
    echo "fetch-trust-anchor: the anchor does not match its pinned digest" >&2
    echo "  expected $SHA256" >&2
    echo "  got      $GOT" >&2
    echo "  Either the pin is stale or the response was substituted. Both" >&2
    echo "  are refusals." >&2
    exit 1
fi

if ! grep -q "BEGIN PUBLIC KEY" "$TMP"; then
    echo "fetch-trust-anchor: fetched bytes are not a PEM public key" >&2
    exit 1
fi

install -m 0644 "$TMP" "$OUT"
echo "    digest $GOT matches the pin"
echo "==> anchor written to $OUT"
