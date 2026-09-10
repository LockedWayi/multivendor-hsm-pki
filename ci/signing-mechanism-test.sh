#!/usr/bin/env bash
#
# Prove the PKCS#11 signing path end to end, against a throwaway registry.
#
#   ci/signing-mechanism-test.sh [<local image tag> <sbom.cdx.json>]
#
# Without arguments it builds and scans the image itself.
#
#   1. start a registry container on a free localhost port
#   2. provision a fresh SoftHSM2 token set and a signed inventory under
#      .local/mechanism, with random PINs that never leave this process
#   3. push the image, sign it with image-signing-key-v1 over PKCS#11,
#      attest the SBOM and a provenance predicate with the same key
#   4. sign the extracted binary with artifact-signing-key-v1
#   5. verify all of it with public keys only: ci/verify-run-artifacts.sh
#   6. run ci/verify-release.sh against the run's own anchor, served from a
#      local HTTP server, and check its refusals:
#        - an unsigned image
#        - an image with a signature but no attestations
#        - an expired inventory
#        - a re-signed inventory under an anchor the consumer did not accept
#      and that the correct tree passes
#
# Nothing here reaches a public registry or a transparency log. The keys
# die with the run. This proves the mechanism, not custody.
#
# Provenance needs the GITHUB_* variables. Outside a pipeline this script
# sets placeholders naming mechanism-test.invalid, so the predicate cannot
# be mistaken for a real one. It never leaves the throwaway registry.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"

die() { echo "signing-mechanism-test: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
step() { printf '\n\033[1m    -- %s\033[0m\n' "$*"; }

WORK="$REPO_ROOT/.local/mechanism"
WORK_REL=".local/mechanism"
IMAGE="${1:-}"
SBOM="${2:-}"

REGISTRY_CID=""
ANCHOR_PID=""
cleanup() {
    [ -z "$REGISTRY_CID" ] || docker rm -f "$REGISTRY_CID" >/dev/null 2>&1 || true
    [ -z "$ANCHOR_PID" ] || kill "$ANCHOR_PID" >/dev/null 2>&1 || true
    unset SUPPLY_PIN INVENTORY_PIN COSIGN_PKCS11_PIN
}
trap cleanup EXIT

# expect_fail <substring> <name> -- <command>: the command must exit
# non-zero and print the substring. A verifier nobody has watched refuse
# proves nothing.
expect_fail() {
    local want="$1" name="$2"; shift 2
    [ "$1" = "--" ] && shift
    local out status
    out="$("$@" 2>&1)" && status=0 || status=$?
    if [ "$status" -eq 0 ]; then
        printf '%s\n' "$out" >&2
        die "$name: expected a refusal, got exit 0"
    fi
    if ! printf '%s' "$out" | grep -qF "$want"; then
        printf '%s\n' "$out" >&2
        die "$name: refused, but not for the stated reason (wanted '$want')"
    fi
    echo "    refused: $name"
}

log "preparing $WORK_REL"
# Token directories are root-owned 0700; removed from a container.
if [ -d "$WORK" ]; then
    docker run --rm -v "$REPO_ROOT/.local":/local "$ALPINE_IMAGE" rm -rf /local/mechanism
fi
mkdir -p "$WORK"

log "1/6  starting a throwaway registry"
REGISTRY_CID="$(docker run -d -p 127.0.0.1:0:5000 "$REGISTRY_IMAGE")"
PORT="$(docker port "$REGISTRY_CID" 5000/tcp | head -1 | sed 's/.*://')"
REGISTRY="localhost:$PORT"
for _ in $(seq 1 30); do
    curl -fsS "http://$REGISTRY/v2/" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -fsS "http://$REGISTRY/v2/" >/dev/null || die "the throwaway registry did not come up on $REGISTRY"
echo "    $REGISTRY"

log "2/6  provisioning a throwaway token set and a signed inventory"
SUPPLY_PIN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
INVENTORY_PIN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HSM_PKI_SUPPLY_PIN_VALUE="$SUPPLY_PIN" HSM_PKI_INVENTORY_PIN_VALUE="$INVENTORY_PIN" \
HSM_PKI_SIGNING_STATE="$WORK/signing" HSM_PKI_KEYS_DIR="$WORK/keys" \
    "$REPO_ROOT/deploy/docker/provision-signing-keys.sh" >/dev/null
echo "    keys under $WORK_REL/keys"

if [ -z "$IMAGE" ]; then
    log "building and scanning the image"
    IMAGE="hsm-pki-server:mechanism"
    docker build -q -f "$REPO_ROOT/deploy/docker/Dockerfile" -t "$IMAGE" "$REPO_ROOT" >/dev/null
    "$REPO_ROOT/ci/scan-image.sh" "$IMAGE" >/dev/null
    SBOM="${HSM_PKI_SCAN_OUT:-$REPO_ROOT/.local/scan}/sbom.cdx.json"
fi
[ -f "$SBOM" ] || die "no SBOM at $SBOM"
SBOM_REL="$(realpath --relative-to="$REPO_ROOT" -- "$SBOM")"
case "$SBOM_REL" in ../*) die "the SBOM must be inside the repository" ;; esac

# Provenance placeholders outside a pipeline.
if [ -z "${GITHUB_ACTIONS:-}" ]; then
    export GITHUB_REPOSITORY="mechanism-test.invalid/repository"
    export GITHUB_SHA="${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
    export GITHUB_RUN_ID="0" GITHUB_RUN_ATTEMPT="0" GITHUB_REF="refs/heads/none"
    export GITHUB_SERVER_URL="https://mechanism-test.invalid"
    export GITHUB_WORKFLOW_REF="mechanism-test.invalid/repository/.github/workflows/ci.yml@refs/heads/none"
    export GITHUB_EVENT_NAME="mechanism-test"
fi
"$REPO_ROOT/ci/generate-provenance.sh" "$WORK/provenance.json" >/dev/null

# The run's anchor, served the way the real one is fetched: a path of
# <repo>/<commit>/<file> under a base URL, pinned by commit and digest.
ANCHOR_REPO="mechanism/anchor"
ANCHOR_COMMIT="$(sha1sum "$WORK/keys/inventory-signing-key-v1.pub" | cut -d' ' -f1)"
ANCHOR_SHA256="$(sha256sum "$WORK/keys/inventory-signing-key-v1.pub" | cut -d' ' -f1)"
mkdir -p "$WORK/anchor-www/$ANCHOR_REPO/$ANCHOR_COMMIT"
cp "$WORK/keys/inventory-signing-key-v1.pub" "$WORK/anchor-www/$ANCHOR_REPO/$ANCHOR_COMMIT/"
python3 -u -m http.server --bind 127.0.0.1 --directory "$WORK/anchor-www" 0 > "$WORK/anchor-www.log" 2>&1 &
ANCHOR_PID=$!
ANCHOR_PORT=""
for _ in $(seq 1 30); do
    ANCHOR_PORT="$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$WORK/anchor-www.log" | head -1)"
    [ -n "$ANCHOR_PORT" ] && break
    sleep 0.2
done
[ -n "$ANCHOR_PORT" ] || die "the anchor server did not report a port"
export HSM_PKI_TRUST_ANCHOR_BASE_URL="http://127.0.0.1:$ANCHOR_PORT"
export HSM_PKI_TRUST_ANCHOR_REPO="$ANCHOR_REPO"
export HSM_PKI_TRUST_ANCHOR_COMMIT="$ANCHOR_COMMIT"
export HSM_PKI_TRUST_ANCHOR_SHA256="$ANCHOR_SHA256"
export HSM_PKI_REGISTRY_ALLOW_HTTP=true
verify_release() { HSM_PKI_KEYS_DIR="$WORK/keys" "$REPO_ROOT/ci/verify-release.sh" "$@"; }

log "3/6  pushing, signing and attesting over PKCS#11"
docker tag "$IMAGE" "$REGISTRY/hsm-pki-server:mechanism"
docker push -q "$REGISTRY/hsm-pki-server:mechanism" >/dev/null
DIGEST="$(docker inspect "$REGISTRY/hsm-pki-server:mechanism" \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    | grep "^$REGISTRY/hsm-pki-server@" | head -1 | cut -d@ -f2)"
[ -n "$DIGEST" ] || die "could not resolve the pushed image's digest"
DIGEST_REF="$REGISTRY/hsm-pki-server@$DIGEST"
echo "    $DIGEST_REF"

export HSM_PKI_SIGNING_STATE="$WORK/signing" HSM_PKI_KEYS_DIR="$WORK/keys"
export COSIGN_PKCS11_PIN="$SUPPLY_PIN"

step "an unsigned image is refused"
expect_fail "no key in the verified inventory produced this image's signature" \
    "unsigned image" -- verify_release "$DIGEST_REF"

step "sign the image with image-signing-key-v1"
"$REPO_ROOT/ci/sign-image.sh" "$DIGEST_REF" >/dev/null

step "a signature without attestations is refused"
expect_fail "these attestations are missing" \
    "signed image, no attestations" -- verify_release "$DIGEST_REF"

step "attest the SBOM and the provenance with the same key"
"$REPO_ROOT/ci/attest-image.sh" "$DIGEST_REF" "$SBOM" "$WORK/provenance.json" >/dev/null

step "the complete chain passes"
verify_release "$DIGEST_REF" >/dev/null || die "the complete chain did not verify"
echo "    VERIFIED"

step "the predicate read back from the registry is the SBOM that was attested"
HSM_PKI_COSIGN_VERSION=v2 HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" verify-attestation \
    --key "/repo/$WORK_REL/keys/image-signing-key-v1.pub" --type cyclonedx \
    --insecure-ignore-tlog=true --allow-http-registry=true "$DIGEST_REF" > "$WORK/sbom.dsse.json" 2>/dev/null
"$REPO_ROOT/ci/extract-predicate.sh" "$WORK/sbom.dsse.json" "$DIGEST" "$WORK/sbom.readback.json" >/dev/null
python3 - "$SBOM" "$WORK/sbom.readback.json" <<'PY' || die "the predicate read back differs from the attested SBOM"
import json, sys
a, b = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
sys.exit(0 if a == b else 1)
PY
echo "    identical"

log "4/6  signing the extracted binary with artifact-signing-key-v1"
mkdir -p "$WORK/release"
BINARY="$WORK/release/hsm-pki-server"
cid="$(docker create "$IMAGE")"
docker cp "$cid:/usr/local/bin/hsm-pki-server" "$BINARY" >/dev/null
docker rm -f "$cid" >/dev/null
chmod 0755 "$BINARY"
env -u HSM_PKI_COSIGN_VERSION "$REPO_ROOT/ci/sign-artifact.sh" "$BINARY" "$BINARY.bundle" >/dev/null
echo "    $WORK_REL/release/hsm-pki-server.bundle"

log "5/6  verifying everything with public keys only"
env -u COSIGN_PKCS11_PIN -u HSM_PKI_SIGNING_STATE \
    "$REPO_ROOT/ci/verify-run-artifacts.sh" "$WORK/keys" "$BINARY" "$BINARY.bundle" "$DIGEST_REF" "$GITHUB_SHA" >/dev/null \
    || die "ci/verify-run-artifacts.sh failed"
echo "    all checks and refusals held"

log "6/6  the release verifier's refusals"
unset COSIGN_PKCS11_PIN

step "an expired inventory is refused with the generator's wording"
# A test anchor made with openssl, because the inventory token is offline
# and an expired document is not something the keytool will sign.
EXPIRED="$WORK/expired"
mkdir -p "$EXPIRED"
openssl ecparam -name prime256v1 -genkey -noout -out "$EXPIRED/anchor.key" 2>/dev/null
openssl ec -in "$EXPIRED/anchor.key" -pubout -out "$EXPIRED/inventory-signing-key-v1.pub" 2>/dev/null
python3 - "$WORK/keys/key-inventory.json" "$EXPIRED/key-inventory.json" <<'PY'
import json, sys
inv = json.load(open(sys.argv[1]))
inv["generated_at"] = "1999-01-01T00:00:00Z"
inv["valid_until"] = "2000-01-01T00:00:00Z"
for k in inv["keys"]:
    k["valid_from"] = "1999-01-01T00:00:00Z"
with open(sys.argv[2], "w") as fh:
    json.dump(inv, fh, indent=2)
    fh.write("\n")
PY
openssl dgst -sha256 -sign "$EXPIRED/anchor.key" -out "$EXPIRED/key-inventory.json.sig" "$EXPIRED/key-inventory.json"
EXPIRED_COMMIT="$(sha1sum "$EXPIRED/inventory-signing-key-v1.pub" | cut -d' ' -f1)"
mkdir -p "$WORK/anchor-www/$ANCHOR_REPO/$EXPIRED_COMMIT"
cp "$EXPIRED/inventory-signing-key-v1.pub" "$WORK/anchor-www/$ANCHOR_REPO/$EXPIRED_COMMIT/"
expect_fail "the inventory expired at 2000-01-01T00:00:00Z" "expired inventory" -- \
    env HSM_PKI_KEYS_DIR="$EXPIRED" \
        HSM_PKI_TRUST_ANCHOR_COMMIT="$EXPIRED_COMMIT" \
        HSM_PKI_TRUST_ANCHOR_SHA256="$(sha256sum "$EXPIRED/inventory-signing-key-v1.pub" | cut -d' ' -f1)" \
        "$REPO_ROOT/ci/verify-release.sh" --inventory-only
rm -f "$EXPIRED/anchor.key"

step "a re-signed inventory is refused under the anchor the consumer holds"
ATTACKER="$WORK/attacker"
mkdir -p "$ATTACKER"
openssl ecparam -name prime256v1 -genkey -noout -out "$ATTACKER/inventory.key" 2>/dev/null
openssl ec -in "$ATTACKER/inventory.key" -pubout -out "$ATTACKER/inventory-signing-key-v1.pub" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$ATTACKER/image.key" 2>/dev/null
openssl ec -in "$ATTACKER/image.key" -pubout -out "$ATTACKER/image-signing-key-v1.pub" 2>/dev/null
python3 - "$WORK/keys/key-inventory.json" "$ATTACKER/image-signing-key-v1.pub" "$ATTACKER/key-inventory.json" <<'PY'
import json, sys
inv = json.load(open(sys.argv[1]))
pem = open(sys.argv[2]).read()
for k in inv["keys"]:
    if k["label"] == "image-signing-key-v1":
        k["public_key"] = pem
with open(sys.argv[3], "w") as fh:
    json.dump(inv, fh, indent=2)
    fh.write("\n")
PY
openssl dgst -sha256 -sign "$ATTACKER/inventory.key" -out "$ATTACKER/key-inventory.json.sig" "$ATTACKER/key-inventory.json"
expect_fail "the key inventory does not verify against the anchor" "re-signed inventory" -- \
    env HSM_PKI_KEYS_DIR="$ATTACKER" "$REPO_ROOT/ci/verify-release.sh" --inventory-only
rm -f "$ATTACKER/inventory.key" "$ATTACKER/image.key"

step "the correct tree still passes"
verify_release --inventory-only >/dev/null || die "the correct tree did not verify"
echo "    INVENTORY VERIFIED"

cat <<EOT

The PKCS#11 signing path works end to end against a throwaway registry, and
every refusal of the release verifier held.

  registry   $REGISTRY (removed now)
  image      $DIGEST_REF
  keys       $WORK_REL/keys (ephemeral; not the published ones)
EOT
