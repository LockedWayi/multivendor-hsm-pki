#!/usr/bin/env bash
#
# Provision the supply-chain signing keys and publish the signed key
# inventory: one command, no hardware, no proprietary SDK.
#
# It creates two SoftHSM2 tokens and three keys:
#
#   supply-chain token          offline inventory token
#     image-signing-key-v1        inventory-signing-key-v1
#     artifact-signing-key-v1              |
#              |                           | signs
#              +----- listed in ---->  docs/keys/key-inventory.json
#
# Neither signing key shares a token with a CA key. PKCS#11 authenticates
# a token, not a key, so a process holding the CA's session could find and
# use them. hsm-pki-keytool refuses such a token.
#
# The key that signs the inventory is not one of the keys it vouches for,
# and does not live on their token. Step 6 moves that token out of the
# store.
#
# Every published artifact is public: three public keys, one JSON
# document, one signature. No private key is written anywhere.
#
# Both token PINs come from the environment and are required:
#
#   HSM_PKI_SUPPLY_PIN_VALUE=... HSM_PKI_INVENTORY_PIN_VALUE=... \
#       deploy/docker/provision-signing-keys.sh          provision (first run)
#
#   HSM_PKI_SUPPLY_PIN_VALUE=... HSM_PKI_INVENTORY_PIN_VALUE=... \
#       deploy/docker/provision-signing-keys.sh --reset  destroy and re-provision
#
# Re-running without --reset is refused: the labels are taken, and
# regenerating a key under a published label would strand every signature
# made with the old one.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"
STATE="${HSM_PKI_SIGNING_STATE:-$REPO_ROOT/.local/signing}"
# Where the public half of everything provisioned here is written.
# Overridable for the mechanism test, which provisions throwaway keys that
# must not overwrite the published ones.
KEYS_DIR="${HSM_PKI_KEYS_DIR:-$REPO_ROOT/docs/keys}"

# The keytool runs in a container with the repository mounted at /repo.
case "$KEYS_DIR" in
    "$REPO_ROOT"/*)
        KEYS_DIR_IN_REPO="/repo/${KEYS_DIR#"$REPO_ROOT"/}"
        # What the closing summary prints.
        KEYS_DIR_REL="${KEYS_DIR#"$REPO_ROOT"/}" ;;
    *)
        echo "HSM_PKI_KEYS_DIR must be inside $REPO_ROOT: the provisioning" >&2
        echo "containers mount only the repository, so a path outside it" >&2
        echo "resolves against the container's own filesystem and the keys" >&2
        echo "would be written somewhere the host never sees." >&2
        exit 1 ;;
esac
DEV_IMAGE="hsm-pki-dev:local"

SUPPLY_TOKEN_LABEL="hsm-pki-local-supply-chain"
INVENTORY_TOKEN_LABEL="hsm-pki-local-inventory"

# The caller supplies both PINs. They are passed to the containers as
# environment variables and never written to a file; the tool takes the name
# of the variable, not its value.
#
# Not defaulted, and specifically not defaulted to something random: these
# tokens outlive the run. Every later signature -- ci/sign-image.sh,
# ci/sign-artifact.sh, ci/countersign-release.sh, and re-signing the
# inventory during a rotation -- logs back in with these PINs. A PIN this
# script invented and nobody recorded leaves keys that exist, are published
# in the inventory, and can never be used again. Key generation cannot be
# undone by re-running it: the labels are taken.
missing=()
[ -n "${HSM_PKI_SUPPLY_PIN_VALUE:-}" ] || missing+=(HSM_PKI_SUPPLY_PIN_VALUE)
[ -n "${HSM_PKI_INVENTORY_PIN_VALUE:-}" ] || missing+=(HSM_PKI_INVENTORY_PIN_VALUE)
if [ ${#missing[@]} -ne 0 ]; then
    cat >&2 <<'USAGE'
provision-signing-keys: both token PINs must be supplied in the environment.
Missing:
USAGE
    printf '  %s\n' "${missing[@]}" >&2
    cat >&2 <<'USAGE'

Set them to values you can produce again later, and keep them where you keep
your own secrets -- not in this repository, and not in a file beside the
tokens:

  HSM_PKI_SUPPLY_PIN_VALUE=... HSM_PKI_INVENTORY_PIN_VALUE=... \
      deploy/docker/provision-signing-keys.sh

HSM_PKI_SUPPLY_PIN_VALUE guards image-signing-key-v1 and
artifact-signing-key-v1, and is the PIN every later signing step needs as
COSIGN_PKCS11_PIN. HSM_PKI_INVENTORY_PIN_VALUE guards
inventory-signing-key-v1 on the offline token, and is what a rotation needs
to sign the next inventory.
USAGE
    exit 1
fi

SUPPLY_PIN="$HSM_PKI_SUPPLY_PIN_VALUE"
INVENTORY_PIN="$HSM_PKI_INVENTORY_PIN_VALUE"

# Different tokens, different PINs. One PIN over both would make the offline
# inventory token reachable by whatever holds the supply-chain token's.
[ "$SUPPLY_PIN" != "$INVENTORY_PIN" ] || {
    echo "provision-signing-keys: the two tokens must not share a PIN." >&2
    exit 1
}

IMAGE_KEY_LABEL="image-signing-key-v1"
ARTIFACT_KEY_LABEL="artifact-signing-key-v1"
INVENTORY_KEY_LABEL="inventory-signing-key-v1"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if [[ "${1:-}" == "--reset" ]]; then
    log "removing local signing state at $STATE"
    # Removed from inside a container: the token directories are root-owned.
    if [[ -d "$STATE" ]]; then
        docker run --rm -v "$(dirname "$STATE")":/parent "$ALPINE_IMAGE" \
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
    echo "regenerating -v1." >&2
    exit 1
fi

log "building the dev image"
docker build -q -f "$REPO_ROOT/ci/softhsm2-dev.Dockerfile" -t "$DEV_IMAGE" "$REPO_ROOT"

mkdir -p "$STATE"/{pkcs11,etc,tokens,offline-inventory-token} "$KEYS_DIR"

log "extracting the SoftHSM2 module"
# Copied out of the dev image, so this works with no softhsm2 on the host.
# The path inside the image is the real object, not Debian's symlink.
cid="$(docker create "$DEV_IMAGE" /bin/true)"
docker cp "$cid:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" "$STATE/pkcs11/libsofthsm2.so"
docker rm -f "$cid" >/dev/null

cat > "$STATE/etc/softhsm2.conf" <<EOF
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = ERROR
EOF

# keytool runs from the dev image. It is not in the service image.
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
# Two tokens, not two labels on one token.
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
    -public-key-out "$KEYS_DIR_IN_REPO/$IMAGE_KEY_LABEL.pub"

log "3/6  provisioning $ARTIFACT_KEY_LABEL"
# A separate invocation and therefore a separate C_Initialize. The tool
# compares the new key against the others on the token and refuses a
# repeat: ProtectToolkit-C software emulation hands every process the same
# first key.
keytool provision-signing-key \
    -module /pkcs11/libsofthsm2.so \
    -workspace "'$SUPPLY_TOKEN_LABEL'" \
    -pin-env HSM_PKI_SUPPLY_PIN \
    -key-label "$ARTIFACT_KEY_LABEL" \
    -public-key-out "$KEYS_DIR_IN_REPO/$ARTIFACT_KEY_LABEL.pub"

log "4/6  provisioning $INVENTORY_KEY_LABEL on the offline token"
keytool provision-signing-key \
    -module /pkcs11/libsofthsm2.so \
    -workspace "'$INVENTORY_TOKEN_LABEL'" \
    -pin-env HSM_PKI_INVENTORY_PIN \
    -key-label "$INVENTORY_KEY_LABEL" \
    -public-key-out "$KEYS_DIR_IN_REPO/$INVENTORY_KEY_LABEL.pub"

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
    -out "$KEYS_DIR_IN_REPO/key-inventory.json" \
    -signature-out "$KEYS_DIR_IN_REPO/key-inventory.json.sig"

log "verifying the inventory the way a stranger would"
# openssl, not this repository's code.
docker run --rm -v "$KEYS_DIR":/keys:ro "$DEV_IMAGE" \
    openssl dgst -sha256 \
        -verify "/keys/$INVENTORY_KEY_LABEL.pub" \
        -signature /keys/key-inventory.json.sig \
        /keys/key-inventory.json

log "6/6  taking the inventory token offline"
# Identify the token directory by the label stored in it, refuse anything
# but exactly one match, and move it out of the store. In a container,
# because the token directories are 0700 root-owned.
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

Done. Published to $KEYS_DIR_REL/ -- all public, all committable:

  $IMAGE_KEY_LABEL.pub       verifies container image signatures
  $ARTIFACT_KEY_LABEL.pub    verifies release artifact signatures
  $INVENTORY_KEY_LABEL.pub   verifies the inventory itself (pin this out of band)
  key-inventory.json            what a verifier is allowed to trust
  key-inventory.json.sig        detached signature over the file's exact bytes

Private key material stayed on the tokens under $STATE and was never
written anywhere. The inventory token now sits in
$STATE/offline-inventory-token and is not in the store the
supply-chain token is reached through. Signing a new inventory means
bringing it back.

Anyone can check the inventory with nothing but openssl:

  openssl dgst -sha256 -verify $KEYS_DIR_REL/$INVENTORY_KEY_LABEL.pub \\
      -signature $KEYS_DIR_REL/key-inventory.json.sig $KEYS_DIR_REL/key-inventory.json

To rotate a key later, provision the next version and regenerate:

  hsm-pki-keytool provision-signing-key ... -key-label image-signing-key-vNEXT
  hsm-pki-keytool generate-inventory ... -in $KEYS_DIR_REL/key-inventory.json \\
      -key image:$IMAGE_KEY_LABEL:verify-only \\
      -key image:image-signing-key-vNEXT:active ...

(vNEXT stands for the next version number. A concrete label here would be
flagged by internal/keyaudit as a key the inventory does not list.)
EOF
