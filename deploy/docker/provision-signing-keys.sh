#!/usr/bin/env bash
#
# Provision the supply-chain signing keys and publish the signed key
# inventory -- one command, no hardware, no proprietary SDK.
#
# This is the operator-facing half of Phase 4.8. It creates two SoftHSM2
# tokens and three keys, and the arrangement is the whole point:
#
#   supply-chain token          offline inventory token
#     image-signing-key-v1        inventory-signing-key-v1
#     artifact-signing-key-v1              |
#              |                           | signs
#              +----- listed in ---->  docs/keys/key-inventory.json
#
# Three properties an operator should be able to see in what follows:
#
#   1. Neither signing key shares a token with a CA key. PKCS#11
#      authenticates a *token*, not a key, so a process holding the CA's
#      session could otherwise find and use them (docs/threat-model.md
#      6.1). hsm-pki-keytool refuses such a token rather than trusting the
#      operator to point at the right one.
#
#   2. The key that signs the inventory is not one of the keys it vouches
#      for, and does not live on their token. An anchor stored beside what
#      it authorises authorises whoever holds the token -- the invariant
#      behind TUF's offline root role and behind any offline X.509 root.
#      Step 6 moves that token out of the store, so what remains reachable
#      is exactly what CI needs and nothing more.
#
#   3. Every published artifact here is public. Three public keys, one JSON
#      document, one signature. No private key is written anywhere at any
#      point (CLAUDE.md 3.1).
#
# Usage:
#   deploy/docker/provision-signing-keys.sh          provision (first run)
#   deploy/docker/provision-signing-keys.sh --reset  destroy local key state
#                                                    and start over
#
# Re-running without --reset is refused: the labels are taken, and
# regenerating a key under a published label would strand every signature
# made with the old one (CLAUDE.md 3.7 -- rotation provisions the next
# version, it does not overwrite).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="${HSM_PKI_SIGNING_STATE:-$REPO_ROOT/.local/signing}"
KEYS_DIR="$REPO_ROOT/docs/keys"
DEV_IMAGE="hsm-pki-dev:local"

SUPPLY_TOKEN_LABEL="hsm-pki-local-supply-chain"
INVENTORY_TOKEN_LABEL="hsm-pki-local-inventory"

# Throwaway PINs for throwaway local tokens, passed to the containers as
# environment variables and never written to any file. Nothing here is a
# secret worth protecting; the point is that the mechanism is the one a real
# deployment uses -- the tool takes the NAME of the variable, never a value
# on a command line where it would reach ps output and shell history.
SUPPLY_PIN="1234"
INVENTORY_PIN="1234"

IMAGE_KEY_LABEL="image-signing-key-v1"
ARTIFACT_KEY_LABEL="artifact-signing-key-v1"
INVENTORY_KEY_LABEL="inventory-signing-key-v1"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if [[ "${1:-}" == "--reset" ]]; then
    log "removing local signing state at $STATE"
    # Removed from inside a container: SoftHSM2 creates each token
    # directory mode 0700 owned by whoever initialized it, which here is
    # root, so a host-side rm would need sudo from the reader.
    if [[ -d "$STATE" ]]; then
        docker run --rm -v "$(dirname "$STATE")":/parent alpine:3 \
            rm -rf "/parent/$(basename "$STATE")"
    fi
    rm -f "$KEYS_DIR/$IMAGE_KEY_LABEL.pub" "$KEYS_DIR/$ARTIFACT_KEY_LABEL.pub" \
        "$KEYS_DIR/$INVENTORY_KEY_LABEL.pub" \
        "$KEYS_DIR/key-inventory.json" "$KEYS_DIR/key-inventory.json.sig"
    shift
fi

if [[ -d "$STATE" ]]; then
    echo "signing state already exists at $STATE." >&2
    echo "Re-run with --reset to discard it, or leave it alone: the key labels" >&2
    echo "are already taken, and rotation means provisioning -v2 rather than" >&2
    echo "regenerating -v1 (CLAUDE.md 3.7)." >&2
    exit 1
fi

log "building the dev image"
docker build -q -f "$REPO_ROOT/ci/softhsm2-dev.Dockerfile" -t "$DEV_IMAGE" "$REPO_ROOT"

mkdir -p "$STATE"/{pkcs11,etc,tokens,offline-inventory-token} "$KEYS_DIR"

log "extracting the SoftHSM2 module"
# Copied out of the dev image rather than mounted from the host, so this
# works on a machine with no softhsm2 installed. The path inside the image
# is the real object, not Debian's /usr/lib/softhsm symlink: mounting the
# symlink reproduces a dangling link inside the container, which fails
# exactly like a missing module.
cid="$(docker create "$DEV_IMAGE" /bin/true)"
docker cp "$cid:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" "$STATE/pkcs11/libsofthsm2.so"
docker rm -f "$cid" >/dev/null

cat > "$STATE/etc/softhsm2.conf" <<EOF
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = ERROR
EOF

# keytool runs from the dev image, which stands in for an operator's
# workstation. It is not in the service image and never will be.
keytool() {
    docker run --rm \
        -v "$REPO_ROOT":/repo -w /repo \
        -v "$STATE/tokens":/var/lib/softhsm/tokens \
        -v "$STATE/pkcs11":/pkcs11:ro \
        -v "$STATE/etc":/conf:ro \
        -e SOFTHSM2_CONF=/conf/softhsm2.conf \
        -e HSM_PKI_SUPPLY_PIN="$SUPPLY_PIN" \
        -e HSM_PKI_INVENTORY_PIN="$INVENTORY_PIN" \
        "$DEV_IMAGE" sh -c "
            git config --global --add safe.directory /repo
            go run ./cmd/hsm-pki-keytool $*
        "
}

log "1/6  initializing two tokens"
# Two tokens, not two labels on one token. What separates the supply-chain
# keys from the key that vouches for them is a custody boundary, and a label
# is not one.
docker run --rm \
    -v "$STATE/tokens":/var/lib/softhsm/tokens \
    -v "$STATE/etc":/conf:ro \
    -e SOFTHSM2_CONF=/conf/softhsm2.conf \
    "$DEV_IMAGE" sh -c "
        softhsm2-util --init-token --free --label '$SUPPLY_TOKEN_LABEL' \
            --so-pin '$SUPPLY_PIN' --pin '$SUPPLY_PIN' >/dev/null
        softhsm2-util --init-token --free --label '$INVENTORY_TOKEN_LABEL' \
            --so-pin '$INVENTORY_PIN' --pin '$INVENTORY_PIN' >/dev/null
        softhsm2-util --show-slots | grep -E 'Label:|Serial'
    "

log "2/6  provisioning $IMAGE_KEY_LABEL"
keytool provision-signing-key \
    -module /pkcs11/libsofthsm2.so \
    -workspace "'$SUPPLY_TOKEN_LABEL'" \
    -pin-env HSM_PKI_SUPPLY_PIN \
    -key-label "$IMAGE_KEY_LABEL" \
    -public-key-out "/repo/docs/keys/$IMAGE_KEY_LABEL.pub"

log "3/6  provisioning $ARTIFACT_KEY_LABEL"
# A separate invocation, and therefore a separate key. The tool compares the
# key it just generated against the others on the token and refuses a
# repeat, because a token whose RNG restarts per C_Initialize hands out the
# same key to each process -- measured on ProtectToolkit's software
# emulator, docs/lessons.md 8.
keytool provision-signing-key \
    -module /pkcs11/libsofthsm2.so \
    -workspace "'$SUPPLY_TOKEN_LABEL'" \
    -pin-env HSM_PKI_SUPPLY_PIN \
    -key-label "$ARTIFACT_KEY_LABEL" \
    -public-key-out "/repo/docs/keys/$ARTIFACT_KEY_LABEL.pub"

log "4/6  provisioning $INVENTORY_KEY_LABEL on the offline token"
keytool provision-signing-key \
    -module /pkcs11/libsofthsm2.so \
    -workspace "'$INVENTORY_TOKEN_LABEL'" \
    -pin-env HSM_PKI_INVENTORY_PIN \
    -key-label "$INVENTORY_KEY_LABEL" \
    -public-key-out "/repo/docs/keys/$INVENTORY_KEY_LABEL.pub"

log "5/6  generating and signing the key inventory"
keytool generate-inventory \
    -module /pkcs11/libsofthsm2.so \
    -workspace "'$SUPPLY_TOKEN_LABEL'" \
    -pin-env HSM_PKI_SUPPLY_PIN \
    -inventory-workspace "'$INVENTORY_TOKEN_LABEL'" \
    -inventory-pin-env HSM_PKI_INVENTORY_PIN \
    -inventory-key-label "$INVENTORY_KEY_LABEL" \
    -key "image:$IMAGE_KEY_LABEL:active" \
    -key "artifact:$ARTIFACT_KEY_LABEL:active" \
    -out /repo/docs/keys/key-inventory.json \
    -signature-out /repo/docs/keys/key-inventory.json.sig

log "verifying the inventory the way a stranger would"
# openssl, not this repository's code. A signature checked only by the
# library that produced it proves the code agrees with itself, which it
# would do just as convincingly if the format were wrong (CLAUDE.md 3.10).
docker run --rm -v "$REPO_ROOT/docs/keys":/keys:ro "$DEV_IMAGE" \
    openssl dgst -sha256 \
        -verify "/keys/$INVENTORY_KEY_LABEL.pub" \
        -signature /keys/key-inventory.json.sig \
        /keys/key-inventory.json

log "6/6  taking the inventory token offline"
# The same move run-local.sh makes with the root: identify the token
# directory by the label stored in it, refuse to act on anything but exactly
# one match, and move it out of the store. Resolving an ambiguous match to
# the first hit would let enumeration order decide which token goes in the
# safe, which is nobody's decision (CLAUDE.md 3.8).
#
# In a container because SoftHSM2's token directories are 0700 owned by the
# user that initialized them, so a host-side search reads none of them and
# -- with its errors suppressed -- reports "no match" for a token that is
# plainly there.
docker run --rm -v "$STATE":/state -e INVENTORY_LABEL="$INVENTORY_TOKEN_LABEL" "$DEV_IMAGE" sh -c '
    set -eu
    matches=$(grep -rla -- "$INVENTORY_LABEL" /state/tokens | xargs -r -n1 dirname | sort -u)
    count=$(printf "%s" "$matches" | grep -c . || true)
    if [ "$count" -ne 1 ]; then
        echo "expected exactly one token directory holding $INVENTORY_LABEL, found $count" >&2
        printf "  %s\n" $matches >&2
        exit 1
    fi
    mv "$matches" /state/offline-inventory-token/
    echo "inventory token directory $(basename "$matches") moved out of the store"
'

cat <<EOF

Done. Published to docs/keys/ -- all public, all committable:

  $IMAGE_KEY_LABEL.pub       verifies container image signatures
  $ARTIFACT_KEY_LABEL.pub    verifies release artifact signatures
  $INVENTORY_KEY_LABEL.pub   verifies the inventory itself (pin this out of band)
  key-inventory.json            what a verifier is allowed to trust
  key-inventory.json.sig        detached signature over the file's exact bytes

Private key material stayed on the tokens under $STATE and was never
written anywhere. The inventory token now sits in
$STATE/offline-inventory-token and is not in the store the
supply-chain token is reached through, so signing a new inventory means
deliberately bringing it back.

Anyone can check the inventory with nothing but openssl:

  openssl dgst -sha256 -verify docs/keys/$INVENTORY_KEY_LABEL.pub \\
      -signature docs/keys/key-inventory.json.sig docs/keys/key-inventory.json

To rotate a key later, provision the next version and regenerate:

  hsm-pki-keytool provision-signing-key ... -key-label image-signing-key-vNEXT
  hsm-pki-keytool generate-inventory ... -in docs/keys/key-inventory.json \\
      -key image:$IMAGE_KEY_LABEL:verify-only \\
      -key image:image-signing-key-vNEXT:active ...

(vNEXT stands for the next version number. It is written that way rather
than as a concrete label because ci's key audit reads this file and would
otherwise flag an example key the inventory does not list -- which is the
audit working, on a line that was only ever documentation.)
EOF
