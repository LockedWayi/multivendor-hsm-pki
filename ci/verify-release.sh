#!/usr/bin/env bash
#
# Verify a published image without trusting this repository.
#
#   HSM_PKI_TRUST_ANCHOR_REPO=<owner/name> \
#   HSM_PKI_TRUST_ANCHOR_COMMIT=<commit> \
#   HSM_PKI_TRUST_ANCHOR_SHA256=<digest of the anchor file> \
#   ci/verify-release.sh ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:<digest>
#
#   ci/verify-release.sh --inventory-only      links 1 to 3 only
#
# The chain:
#
#   1. anchor      fetched from the anchor repository at the commit and with
#                  the SHA-256 the caller supplies. Never read from this
#                  tree. An unreachable anchor is a refusal, not a fallback.
#   2. inventory   docs/keys/key-inventory.json checked against the anchor
#                  with openssl.
#   3. keys        read out of the verified inventory by ci/select-key. An
#                  expired inventory is refused. A key that is not yet valid
#                  or is retired is left out.
#   4. image       the signature, the CycloneDX SBOM attestation and the
#                  SLSA provenance attestation, each verified against a key
#                  from step 3 with no token mounted. All three must be
#                  present. An image with only the pipeline's keyless
#                  signature fails here.
#
# What this proves depends on where the anchor inputs came from. Changing
# the anchor file in place needs write access to the anchor repository.
# Replacing the anchor needs the consumer to accept new inputs. A consumer
# who copies the inputs from this repository's README trusts this
# repository for that step.
#
# Environment:
#   HSM_PKI_TRUST_ANCHOR_REPO, _COMMIT, _SHA256   required
#   HSM_PKI_KEYS_DIR              directory holding the inventory, default docs/keys
#   HSM_PKI_REGISTRY_ALLOW_HTTP   plaintext registry, default false
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"
WORK="$REPO_ROOT/.local/verify"

die() { echo "verify-release: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

usage() {
    cat >&2 <<'USAGE'
usage: HSM_PKI_TRUST_ANCHOR_REPO=<owner/name> \
       HSM_PKI_TRUST_ANCHOR_COMMIT=<40-hex commit> \
       HSM_PKI_TRUST_ANCHOR_SHA256=<64-hex digest of the anchor file> \
       ci/verify-release.sh [--inventory-only] <image>@sha256:<digest>

The three anchor inputs are required. They are not read from this tree.
Take them from a source you trust more than this repository.
USAGE
    exit 2
}

INVENTORY_ONLY=0
if [ "${1:-}" = "--inventory-only" ]; then
    INVENTORY_ONLY=1
    shift
fi
REF="${1:-}"

[ -n "${HSM_PKI_TRUST_ANCHOR_REPO:-}" ] || usage
[ -n "${HSM_PKI_TRUST_ANCHOR_COMMIT:-}" ] || usage
[ -n "${HSM_PKI_TRUST_ANCHOR_SHA256:-}" ] || usage
if [ "$INVENTORY_ONLY" = "1" ]; then
    REF="(inventory only)"
else
    [ -n "$REF" ] || usage
    case "$REF" in
        *@sha256:*) ;;
        *) die "refusing to verify a tag: $REF
Pass the digest form. A tag is a pointer somebody can move, so verifying
one says nothing about the bytes anybody else will pull." ;;
    esac
fi

ALLOW_HTTP="${HSM_PKI_REGISTRY_ALLOW_HTTP:-false}"
KEYS_DIR="${HSM_PKI_KEYS_DIR:-$REPO_ROOT/docs/keys}"
case "$KEYS_DIR" in
    "$REPO_ROOT"/*) KEYS_DIR_REL="${KEYS_DIR#"$REPO_ROOT"/}" ;;
    *) die "HSM_PKI_KEYS_DIR must be inside $REPO_ROOT: the key selector runs in a container that mounts only the repository" ;;
esac

# The key selector runs as root in a container. The directory it writes
# into is created here first, so it stays owned by the caller and can be
# emptied by the next run.
ANCHOR="$WORK/anchor.pub"
SELECTED="$WORK/keys"
rm -rf "$SELECTED"
mkdir -p "$SELECTED"

log "1/4  fetching the trust anchor from outside the tree being verified"
"$REPO_ROOT/ci/fetch-trust-anchor.sh" "$ANCHOR"

log "2/4  verifying the key inventory against that anchor, with openssl"
INVENTORY="$KEYS_DIR/key-inventory.json"
INVENTORY_SIG="$KEYS_DIR/key-inventory.json.sig"
[ -f "$INVENTORY" ] || die "no inventory at $INVENTORY"
[ -f "$INVENTORY_SIG" ] || die "no inventory signature at $INVENTORY_SIG"

openssl dgst -sha256 -verify "$ANCHOR" \
    -signature "$INVENTORY_SIG" "$INVENTORY" \
    || die "the key inventory does not verify against the anchor.
Either $KEYS_DIR_REL/ was changed without the offline inventory token, or
the anchor inputs are wrong for this tree. Both are refusals."

log "3/4  selecting the image-signing keys from the verified inventory"
# One selection for every consumer. It refuses an expired inventory and
# leaves out keys that are not yet valid or are retired.
mapfile -t SELECTION < <(goRun ./ci/select-key \
    -inventory "/repo/$KEYS_DIR_REL/key-inventory.json" \
    -purpose image \
    -out-dir "/repo/${SELECTED#"$REPO_ROOT"/}") || die "key selection failed; see the message above"
[ "${#SELECTION[@]}" -gt 0 ] || die "the verified inventory lists no usable image-signing key"
for line in "${SELECTION[@]}"; do
    printf '    %s (%s)\n' "$(cut -f1 <<<"$line")" "$(cut -f2 <<<"$line")"
done

if [ "$INVENTORY_ONLY" = "1" ]; then
    cat <<EOT

INVENTORY VERIFIED (links 1-3 of 4)

The anchor was reachable, the inventory verifies against it, and it names a
usable image-signing key. The image was not checked. Pass a digest instead
of --inventory-only to check a release.
EOT
    exit 0
fi

log "4/4  verifying the signature and both attestations, with no token mounted"
# cosign v2 reads the layout Kyverno reads, so what passes here is what
# admission accepts.
export HSM_PKI_COSIGN_VERSION=v2
"$REPO_ROOT/ci/cosign.sh" fetch >/dev/null

# find_signer <subcommand> [extra args]: prints the label of the first
# selected key that verifies, or nothing.
find_signer() {
    local sub="$1"; shift
    local line label key_rel
    for line in "${SELECTION[@]}"; do
        label="$(cut -f1 <<<"$line")"
        key_rel="${SELECTED#"$REPO_ROOT"/}/$label.pub"
        if HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" "$sub" \
                --key "/repo/$key_rel" --insecure-ignore-tlog=true \
                --allow-http-registry="$ALLOW_HTTP" "$@" \
                "$REF" >/dev/null 2>&1; then
            echo "$label"
            return 0
        fi
    done
    return 1
}

SIGNED_BY="$(find_signer verify || true)"
[ -n "$SIGNED_BY" ] || die \
    "no key in the verified inventory produced this image's signature.

The image is not vouched for by any key this project publishes. A build of
main carries only the pipeline's keyless signature, which admission ignores
and this script does not accept. A release digest is counter-signed by the
maintainer with ci/countersign-release.sh."
echo "    signature       $SIGNED_BY"

SBOM_BY="$(find_signer verify-attestation --type cyclonedx || true)"
PROV_BY="$(find_signer verify-attestation --type slsaprovenance1 || true)"
missing=""
[ -n "$SBOM_BY" ] || missing="$missing CycloneDX-SBOM"
[ -n "$PROV_BY" ] || missing="$missing SLSA-provenance"
[ -z "$missing" ] || die \
    "the image is signed by $SIGNED_BY, but these attestations are missing or not
signed by a key in the verified inventory:$missing

A release carries all three: the signature, the SBOM attestation and the
provenance attestation, all made by the durable key. The pipeline's keyless
attestations do not count here. Run ci/countersign-release.sh, which
re-attests both with the durable key."
echo "    SBOM            $SBOM_BY"
echo "    provenance      $PROV_BY"

cat <<EOT

VERIFIED

  image        $REF
  signed by    $SIGNED_BY
  SBOM by      $SBOM_BY
  provenance   $PROV_BY
  listed in    $KEYS_DIR_REL/key-inventory.json
  anchor       $HSM_PKI_TRUST_ANCHOR_REPO @ $(cut -c1-12 <<<"$HSM_PKI_TRUST_ANCHOR_COMMIT")

The anchor came from outside this tree, the inventory was checked against
it with openssl, and the keys were read out of the inventory.
EOT
