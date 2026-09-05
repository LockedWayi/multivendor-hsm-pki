#!/usr/bin/env bash
#
# Fetch the key-inventory trust anchor from the repository that publishes it,
# and refuse to produce anything else.
#
# # Why the anchor is not simply read from docs/keys/
#
# The inventory, its detached signature and the key that verifies that
# signature all used to live in this tree. Verification then proves the three
# files agree with each other -- which they would also do if somebody who
# could write here rewrote all three together. The signature is real; what was
# missing is that the anchor was not independent of what it authenticates.
#
# The in-repo copy is still right for a developer rendering a policy locally.
# It is the *verifying* path that must not take its anchor from the tree it is
# verifying, so that path uses this script.
#
# # What is pinned, and why each one
#
#   the commit    A branch is a pointer somebody can move; a commit is the
#                 bytes. Pinning a branch would mean trusting whatever that
#                 branch points at on the day the job runs.
#   the digest    The commit pin already fixes the content, so the digest is
#                 belt and braces -- but it is the check that still holds if
#                 the transport, the CDN or the host substitutes a response,
#                 and it costs one hash.
#
# Changing either pin is a change to what this pipeline trusts, and it lands
# in a diff on a file whose history is reviewed. That is the property being
# bought: not that the pins are unreachable, but that moving them is visible
# and that moving the *anchor* needs a second, separately protected
# repository as well.
#
# Usage: ci/fetch-trust-anchor.sh <output-path>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

OUT="${1:?usage: ci/fetch-trust-anchor.sh <output-path>}"
URL="https://raw.githubusercontent.com/${TRUST_ANCHOR_REPO}/${TRUST_ANCHOR_COMMIT}/${TRUST_ANCHOR_FILE}"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "==> fetching the trust anchor"
echo "    ${TRUST_ANCHOR_REPO} @ ${TRUST_ANCHOR_COMMIT}"
# --fail so an HTTP error is an error rather than an error page written to
# the output file, which is the classic way a fetch "succeeds" with a body
# that is not the thing asked for.
if ! curl -fsSL --max-time 30 --retry 2 "$URL" -o "$TMP"; then
    # Fail closed: an unreachable anchor must never fall back to the copy in
    # this tree, because that copy is precisely what this script exists to
    # stop trusting.
    echo "fetch-trust-anchor: could not fetch the anchor from ${URL}" >&2
    echo "  Refusing to continue. Do NOT substitute docs/keys/ -- an anchor" >&2
    echo "  taken from the tree under verification proves nothing." >&2
    exit 1
fi

GOT="$(sha256sum "$TMP" | cut -d' ' -f1)"
if [ "$GOT" != "$TRUST_ANCHOR_SHA256" ]; then
    echo "fetch-trust-anchor: the anchor does not match its pinned digest" >&2
    echo "  expected ${TRUST_ANCHOR_SHA256}" >&2
    echo "  got      ${GOT}" >&2
    echo "  Either the pin is stale or the response was substituted. Both" >&2
    echo "  are refusals, not warnings." >&2
    exit 1
fi

# A PEM public key is the only shape this may be. A digest match already
# implies it, but asserting the shape turns a future mis-pin into a clear
# error rather than a confusing one downstream.
if ! grep -q "BEGIN PUBLIC KEY" "$TMP"; then
    echo "fetch-trust-anchor: fetched bytes are not a PEM public key" >&2
    exit 1
fi

install -m 0644 "$TMP" "$OUT"
echo "    digest ${GOT} matches the pin"
echo "==> anchor written to ${OUT}"
