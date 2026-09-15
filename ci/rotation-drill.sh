#!/usr/bin/env bash
#
# Rotate the image-signing key through its whole lifecycle on a throwaway
# token set, and prove that each state does what the inventory says.
#
#   ci/rotation-drill.sh [<local image tag> <sbom.cdx.json>]
#
# Without arguments it builds and scans the image itself.
#
# The lifecycle is the design: a key is provisioned under a versioned
# label, signs while active, keeps verifying while verify-only, and is
# destroyed on the token when retired. The signed inventory carries the
# state, and every signer and verifier reads the inventory rather than a
# key. Until this script, that was a description. This runs it, with the
# same scripts the pipeline signs and verifies with:
#
#   1. start a throwaway registry
#   2. provision version 1 of every key and inventory version 1
#   3. push the image twice: the copy signed before the roll and the
#      copy signed after it. Same bytes, two signature stores
#   4. sign and attest before-roll with the version the inventory lists
#      as active
#   5. roll: provision the next version, republish the inventory with
#      the old one verify-only (version 2). The signers pick the new
#      version on their own, the old one cannot be forced, both copies
#      verify through the inventory, and the admission policy renders
#      both keys
#   6. retire: calling the old key retired while its private half is on
#      the token is refused. Destroy it with retire-signing-key, which
#      refuses a listing that names another key under the label, and
#      afterwards refuses twice more: the label is gone from the token,
#      then the document says retired. Republish (version 3); the
#      inventory still carries the public key and the retirement date
#   7. signing with it is impossible twice over -- the resolver refuses
#      the label, and the token no longer holds it. Before-roll stops
#      verifying, after-roll still does, the policy renders one key, and
#      rendering the older inventory over it is refused as a rollback
#
# Nothing here reaches a public registry or a transparency log. The keys
# die with the run. This proves the mechanism, with an ephemeral trust
# root; the durable token's rotation is the maintainer's to run.
#
# No image or artifact key version is written in this file. Those labels
# are read from the inventory the run itself published, and the next one
# is derived from the current one. internal/keyaudit refuses a script
# naming a key the published inventory does not list, and a drill should
# not be the reason to weaken that. The inventory signing key is named,
# as deploy/docker/provision-signing-keys.sh names it: the anchor is not
# an entry in the document it signs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"
# shellcheck source=ci/active-signing-key.sh
. "$REPO_ROOT/ci/active-signing-key.sh"

die() { echo "rotation-drill: $*" >&2; exit 1; }
log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
step() { printf '\n\033[1m    -- %s\033[0m\n' "$*"; }

WORK="$REPO_ROOT/.local/rotation"
WORK_REL=".local/rotation"
STATE="$WORK/signing"
KEYS="$WORK/keys"
KEYS_REL="$WORK_REL/keys"
IMAGE="${1:-}"
SBOM="${2:-}"

# Fixed by deploy/docker/provision-signing-keys.sh, which creates them.
DEV_IMAGE="hsm-pki-dev:local"
SUPPLY_TOKEN_LABEL="hsm-pki-local-supply-chain"
INVENTORY_TOKEN_LABEL="hsm-pki-local-inventory"
INVENTORY_KEY_LABEL="inventory-signing-key-v1"

REGISTRY_CID=""
ANCHOR_PID=""
cleanup() {
    [ -z "$REGISTRY_CID" ] || docker rm -f "$REGISTRY_CID" >/dev/null 2>&1 || true
    [ -z "$ANCHOR_PID" ] || kill "$ANCHOR_PID" >/dev/null 2>&1 || true
    unset SUPPLY_PIN INVENTORY_PIN COSIGN_PKCS11_PIN HSM_PKI_SUPPLY_PIN HSM_PKI_INVENTORY_PIN
}
trap cleanup EXIT

# expect_fail <substring> <name> -- <command>: the command must exit
# non-zero and print the substring. A refusal nobody has watched happen
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

# expect_line <extended regex> <name> -- <command>: the command must exit
# 0 and print a line matching the pattern. The pattern names the fact
# being asserted, so a step that succeeds for the wrong reason fails.
expect_line() {
    local want="$1" name="$2"; shift 2
    [ "$1" = "--" ] && shift
    local out status
    out="$("$@" 2>&1)" && status=0 || status=$?
    if [ "$status" -ne 0 ]; then
        printf '%s\n' "$out" >&2
        die "$name: exit $status"
    fi
    if ! printf '%s\n' "$out" | grep -qE "$want"; then
        printf '%s\n' "$out" >&2
        die "$name: succeeded, but did not report '$want'"
    fi
    echo "    ok: $name"
}

# assert_equal <name> <want> <got>
assert_equal() {
    if [ "$2" != "$3" ]; then
        printf 'wanted:\n%s\ngot:\n%s\n' "$2" "$3" >&2
        die "$1"
    fi
    echo "    ok: $1"
}

# The keytool, built once in the dev image and run from it with the token
# store mounted. deploy/docker/provision-signing-keys.sh goes through
# `go run` for each of its four calls; the roll and the retirement need
# eight more, so one build. The Go caches under .local/ci-cache are
# mounted when they exist, as ci/scanner-pins.sh's goRun does.
build_tools() {
    local cache_args=()
    [ -d "$REPO_ROOT/.local/ci-cache/gobuild" ] && cache_args+=(-v "$REPO_ROOT/.local/ci-cache/gobuild":/root/.cache/go-build)
    [ -d "$REPO_ROOT/.local/ci-cache/gomod" ] && cache_args+=(-v "$REPO_ROOT/.local/ci-cache/gomod":/go/pkg/mod)
    mkdir -p "$WORK/bin"
    docker run --rm "${cache_args[@]}" -v "$REPO_ROOT":/repo -w /repo "$DEV_IMAGE" sh -c '
        git config --global --add safe.directory /repo >/dev/null
        go build -o "/repo/$1/bin/" ./cmd/hsm-pki-keytool' sh "$WORK_REL"
}

# tool <binary> [args]: run one of the built tools against the token
# store. The PINs cross into the container by variable name, never as a
# value on the docker command line, where they would reach ps output.
tool() {
    docker run --rm \
        -v "$REPO_ROOT":/repo -w /repo \
        -v "$STATE/tokens":/var/lib/softhsm/tokens \
        -v "$STATE/pkcs11":/pkcs11:ro \
        -v "$STATE/etc":/conf:ro \
        -e SOFTHSM2_CONF=/conf/softhsm2.conf \
        -e HSM_PKI_SUPPLY_PIN -e HSM_PKI_INVENTORY_PIN \
        "$DEV_IMAGE" "/repo/$WORK_REL/bin/$1" "${@:2}"
}
keytool() { tool hsm-pki-keytool "$@"; }

# retire <label> [inventory, repo-relative]: the retirement command, which
# takes its permission from the inventory before it touches the token.
retire() {
    keytool retire-signing-key \
        -module /pkcs11/libsofthsm2.so \
        -workspace "$SUPPLY_TOKEN_LABEL" -pin-env HSM_PKI_SUPPLY_PIN \
        -key-label "$1" -inventory "/repo/${2:-$KEYS_REL/key-inventory.json}"
}

# regenerate_inventory <purpose:label:status>...: republish the inventory
# from the token, in place. The version counter and every valid_from come
# from the document being replaced, which is why -in is required.
regenerate_inventory() {
    local args=() spec
    for spec in "$@"; do args+=(-key "$spec"); done
    keytool generate-inventory \
        -module /pkcs11/libsofthsm2.so \
        -workspace "$SUPPLY_TOKEN_LABEL" -pin-env HSM_PKI_SUPPLY_PIN \
        -inventory-workspace "$INVENTORY_TOKEN_LABEL" -inventory-pin-env HSM_PKI_INVENTORY_PIN \
        -inventory-key-label "$INVENTORY_KEY_LABEL" \
        "${args[@]}" \
        -in "/repo/$KEYS_REL/key-inventory.json" \
        -out "/repo/$KEYS_REL/key-inventory.json" \
        -signature-out "/repo/$KEYS_REL/key-inventory.json.sig"
}

# The inventory token lives outside the store between signings, which is
# what "offline" means for a SoftHSM2 token. Signing the next inventory
# means bringing it back, and taking it out again afterwards. Both moves
# run in a container: the token directories are root-owned.
inventory_token_online() {
    docker run --rm -v "$STATE":/state "$DEV_IMAGE" sh -c '
        set -eu
        count=$(find /state/offline-inventory-token -mindepth 1 -maxdepth 1 -type d | wc -l)
        [ "$count" -eq 1 ] || { echo "expected one offline token directory, found $count" >&2; exit 1; }
        mv /state/offline-inventory-token/* /state/tokens/'
}
inventory_token_offline() {
    docker run --rm -v "$STATE":/state -e INVENTORY_LABEL="$INVENTORY_TOKEN_LABEL" "$DEV_IMAGE" sh -c '
        set -eu
        matches=$(grep -rla -- "$INVENTORY_LABEL" /state/tokens | xargs -r -n1 dirname | sort -u)
        count=$(printf "%s" "$matches" | grep -c . || true)
        [ "$count" -eq 1 ] || { echo "expected exactly one token directory holding $INVENTORY_LABEL, found $count" >&2; exit 1; }
        mv "$matches" /state/offline-inventory-token/'
}

# snapshot_inventory <n>: keep a copy of the document just published, and
# check it carries the version number it should. The copies are what the
# rollback refusal at the end is tested against.
snapshot_inventory() {
    local got
    got="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$KEYS/key-inventory.json")"
    [ "$got" = "$1" ] || die "the inventory just published is version $got, expected $1"
    mkdir -p "$WORK/history"
    cp "$KEYS/key-inventory.json" "$WORK/history/key-inventory.v$1.json"
    cp "$KEYS/key-inventory.json.sig" "$WORK/history/key-inventory.v$1.json.sig"
    echo "    inventory version $1 published"
}

# selection [-active-only]: the image keys ci/select-key returns from the
# current inventory, one "label status" per line. stderr is kept apart
# and only lines carrying select-key's tab separator are read, so a
# docker pull on a cold host cannot be mistaken for a key.
selection() {
    local err lines
    err="$(mktemp)"
    if ! lines="$(goRun ./ci/select-key -inventory "/repo/$KEYS_REL/key-inventory.json" -purpose image "$@" 2>"$err")"; then
        cat "$err" >&2; rm -f "$err"
        return 1
    fi
    rm -f "$err"
    printf '%s\n' "$lines" | grep -F "$(printf '\t')" | cut -f1,2 | tr '\t' ' ' | sort
}

# render_policy <inventory, repo-relative>: render the admission policy
# from that inventory into one fixed output file, so successive renderings
# are subject to the generator's rollback check.
render_policy() {
    local err out
    err="$(mktemp)"
    if ! out="$(goRun ./ci/generate-image-policy \
            -inventory "/repo/$1" \
            -anchor "/repo/$KEYS_REL/$INVENTORY_KEY_LABEL.pub" \
            -out "/repo/$WORK_REL/image-signature.yaml" 2>"$err")"; then
        cat "$err" >&2; rm -f "$err"
        return 1
    fi
    rm -f "$err"
    printf '%s\n' "$out"
}

verify_release() { "$REPO_ROOT/ci/verify-release.sh" "$@"; }

log "preparing $WORK_REL"
# Token directories are root-owned 0700; removed from a container.
if [ -d "$WORK" ]; then
    docker run --rm -v "$REPO_ROOT/.local":/local "$ALPINE_IMAGE" rm -rf /local/rotation
fi
mkdir -p "$WORK"

log "1/7  starting a throwaway registry"
REGISTRY_CID="$(docker run -d -p 127.0.0.1:0:5000 "$REGISTRY_IMAGE")"
PORT="$(docker port "$REGISTRY_CID" 5000/tcp | head -1 | sed 's/.*://')"
REGISTRY="localhost:$PORT"
for _ in $(seq 1 30); do
    curl -fsS "http://$REGISTRY/v2/" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -fsS "http://$REGISTRY/v2/" >/dev/null || die "the throwaway registry did not come up on $REGISTRY"
echo "    $REGISTRY"

log "2/7  provisioning version 1 of every key, and inventory version 1"
SUPPLY_PIN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
INVENTORY_PIN="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export HSM_PKI_SUPPLY_PIN="$SUPPLY_PIN" HSM_PKI_INVENTORY_PIN="$INVENTORY_PIN"
HSM_PKI_SUPPLY_PIN_VALUE="$SUPPLY_PIN" HSM_PKI_INVENTORY_PIN_VALUE="$INVENTORY_PIN" \
HSM_PKI_SIGNING_STATE="$STATE" HSM_PKI_KEYS_DIR="$KEYS" \
    "$REPO_ROOT/deploy/docker/provision-signing-keys.sh" >/dev/null
export HSM_PKI_SIGNING_STATE="$STATE" HSM_PKI_KEYS_DIR="$KEYS" HSM_PKI_REGISTRY_ALLOW_HTTP=true
snapshot_inventory 1

# The labels, as the inventory states them. The next version is derived
# from the current one rather than written here.
V1="$(activeSigningKey image "$KEYS")"
ARTIFACT_KEY="$(activeSigningKey artifact "$KEYS")"
V1_BASE="${V1%-v*}"
V1_NUMBER="${V1##*-v}"
V2="$V1_BASE-v$((V1_NUMBER + 1))"
echo "    image key      $V1 (active)"
echo "    artifact key   $ARTIFACT_KEY (active; not rotated by this drill)"
echo "    next version   $V2"

step "building the keytool once"
build_tools >/dev/null
echo "    $WORK_REL/bin/"

if [ -z "$IMAGE" ]; then
    log "building and scanning the image"
    IMAGE="hsm-pki-server:rotation-drill"
    docker build -q -f "$REPO_ROOT/deploy/docker/Dockerfile" -t "$IMAGE" "$REPO_ROOT" >/dev/null
    "$REPO_ROOT/ci/scan-image.sh" "$IMAGE" >/dev/null
    SBOM="${HSM_PKI_SCAN_OUT:-$REPO_ROOT/.local/scan}/sbom.cdx.json"
fi
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "no local image $IMAGE"
[ -f "$SBOM" ] || die "no SBOM at $SBOM"
SBOM_REL="$(realpath --relative-to="$REPO_ROOT" -- "$SBOM")"
case "$SBOM_REL" in ../*) die "the SBOM must be inside the repository" ;; esac

# Provenance placeholders outside a pipeline, naming an invalid host so
# the predicate cannot be mistaken for a real one.
if [ -z "${GITHUB_ACTIONS:-}" ]; then
    export GITHUB_REPOSITORY="rotation-drill.invalid/repository"
    export GITHUB_SHA="${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
    export GITHUB_RUN_ID="0" GITHUB_RUN_ATTEMPT="0" GITHUB_REF="refs/heads/none"
    export GITHUB_SERVER_URL="https://rotation-drill.invalid"
    export GITHUB_WORKFLOW_REF="rotation-drill.invalid/repository/.github/workflows/ci.yml@refs/heads/none"
    export GITHUB_EVENT_NAME="rotation-drill"
fi
"$REPO_ROOT/ci/generate-provenance.sh" "$WORK/provenance.json" >/dev/null

# The run's anchor, served the way the real one is fetched. The inventory
# signing key does not rotate in this drill, so one anchor covers all
# three inventory versions, which is the point of keeping it apart from
# the keys it vouches for.
ANCHOR_REPO="rotation/anchor"
ANCHOR_COMMIT="$(sha1sum "$KEYS/$INVENTORY_KEY_LABEL.pub" | cut -d' ' -f1)"
ANCHOR_SHA256="$(sha256sum "$KEYS/$INVENTORY_KEY_LABEL.pub" | cut -d' ' -f1)"
mkdir -p "$WORK/anchor-www/$ANCHOR_REPO/$ANCHOR_COMMIT"
cp "$KEYS/$INVENTORY_KEY_LABEL.pub" "$WORK/anchor-www/$ANCHOR_REPO/$ANCHOR_COMMIT/"
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

log "3/7  pushing the image twice: before-roll and after-roll"
# One image, two repositories in the registry. A signature is stored
# beside the digest it covers, per repository, so this gives the two
# copies separate signature stores while keeping one set of bytes.
BEFORE_REPO="$REGISTRY/before-roll"
AFTER_REPO="$REGISTRY/after-roll"
docker tag "$IMAGE" "$BEFORE_REPO:drill"
docker tag "$IMAGE" "$AFTER_REPO:drill"
docker push -q "$BEFORE_REPO:drill" >/dev/null
docker push -q "$AFTER_REPO:drill" >/dev/null
digest_of() {   # digest_of <repo>: the digest the registry holds for <repo>:drill
    docker inspect "$1:drill" --format '{{range .RepoDigests}}{{println .}}{{end}}' \
        | grep "^$1@" | head -1 | cut -d@ -f2
}
BEFORE_REF="$BEFORE_REPO@$(digest_of "$BEFORE_REPO")"
AFTER_REF="$AFTER_REPO@$(digest_of "$AFTER_REPO")"
case "$BEFORE_REF" in *@sha256:*) ;; *) die "could not resolve the before-roll digest" ;; esac
case "$AFTER_REF" in *@sha256:*) ;; *) die "could not resolve the after-roll digest" ;; esac
echo "    $BEFORE_REF"
echo "    $AFTER_REF"

log "4/7  signing before-roll with $V1"
export COSIGN_PKCS11_PIN="$SUPPLY_PIN"
"$REPO_ROOT/ci/sign-image.sh" "$BEFORE_REF" >/dev/null
"$REPO_ROOT/ci/attest-image.sh" "$BEFORE_REF" "$SBOM" "$WORK/provenance.json" >/dev/null
expect_line "signature +$V1\$" "before-roll verifies through inventory version 1, signed by $V1" \
    -- verify_release "$BEFORE_REF"
step "the active key cannot be retired"
expect_fail "rotated, not retired" "retiring $V1 while the inventory lists it as active" \
    -- retire "$V1"

log "5/7  rolling to $V2"
step "provisioning $V2 on the supply-chain token"
expect_line "CKA_SENSITIVE=true CKA_EXTRACTABLE=false" "$V2 generated; the token reports it non-extractable" \
    -- keytool provision-signing-key \
        -module /pkcs11/libsofthsm2.so \
        -workspace "$SUPPLY_TOKEN_LABEL" -pin-env HSM_PKI_SUPPLY_PIN \
        -key-label "$V2" -public-key-out "/repo/$KEYS_REL/$V2.pub"

step "republishing the inventory: $V1 verify-only, $V2 active"
inventory_token_online
regenerate_inventory "image:$V1:verify-only" "image:$V2:active" "artifact:$ARTIFACT_KEY:active" >/dev/null
inventory_token_offline
snapshot_inventory 2

step "the signers follow the inventory, not a constant"
expect_line "^$V2\$" "the resolver now names $V2 for images" -- activeSigningKey image "$KEYS"
expect_line "^$ARTIFACT_KEY\$" "and still $ARTIFACT_KEY for artifacts" -- activeSigningKey artifact "$KEYS"
assert_equal "a verifier may accept $V1 (verify-only) and $V2 (active)" \
    "$(printf '%s active\n%s verify-only' "$V2" "$V1" | sort)" "$(selection)"
assert_equal "a signer may use only $V2" "$V2 active" "$(selection -active-only)"
expect_fail "which the inventory does not list as the" "forcing $V1 through the override" \
    -- env HSM_PKI_IMAGE_KEY_LABEL="$V1" "$REPO_ROOT/ci/sign-image.sh" "$AFTER_REF"

step "signing after-roll with $V2"
"$REPO_ROOT/ci/sign-image.sh" "$AFTER_REF" >/dev/null
"$REPO_ROOT/ci/attest-image.sh" "$AFTER_REF" "$SBOM" "$WORK/provenance.json" >/dev/null

step "both copies verify through inventory version 2"
expect_line "signature +$V1\$" "before-roll, signed by $V1 while it was active" -- verify_release "$BEFORE_REF"
expect_line "signature +$V2\$" "after-roll, signed by $V2" -- verify_release "$AFTER_REF"

step "the admission policy renders both versions"
expect_line "2 trusted image key\(s\) from .* version 2" "policy from inventory version 2" \
    -- render_policy "$KEYS_REL/key-inventory.json"

log "6/7  retiring $V1"
inventory_token_online
step "publishing 'retired' before the key is destroyed is refused"
expect_fail "its private key is still on token" "retired while still on the token" \
    -- regenerate_inventory "image:$V1:retired" "image:$V2:active" "artifact:$ARTIFACT_KEY:active"
cmp -s "$KEYS/key-inventory.json" "$WORK/history/key-inventory.v2.json" \
    || die "the refused regeneration changed the published inventory"
echo "    ok: the refused run wrote nothing"

step "a listing that names another key under the label is refused"
# The inventory of version 2 with a key that is on no token in place of
# the old version's. The label is addressing; the command compares the
# public key on the token with the one the document lists, and destroys
# nothing when they differ.
mkdir -p "$WORK/forged"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/forged/k.pem" 2>/dev/null
python3 - "$KEYS/key-inventory.json" "$WORK/forged/key-inventory.json" "$WORK/forged/k.pem" "$V1" <<'FORGE'
import json, pathlib, subprocess, sys
src, dst, keyfile, label = sys.argv[1:5]
d = json.loads(pathlib.Path(src).read_text())
pub = subprocess.run(["openssl", "ec", "-in", keyfile, "-pubout"], check=True, capture_output=True, text=True).stdout
next(k for k in d["keys"] if k["label"] == label)["public_key"] = pub
pathlib.Path(dst).write_text(json.dumps(d, indent=2) + "\n")
FORGE
rm -f "$WORK/forged/k.pem"
expect_fail "is not the key the inventory lists" "retiring $V1 against a listing of another key" \
    -- retire "$V1" "$WORK_REL/forged/key-inventory.json"

step "destroying $V1 on the token: both halves, by the command that reads the inventory first"
expect_line "private: +destroyed" "$V1 destroyed, private half first" -- retire "$V1"

step "retiring it again is refused: the token no longer holds it"
expect_fail "no key object found" "retiring $V1 a second time" -- retire "$V1"

step "republishing the inventory: $V1 retired, $V2 active"
regenerate_inventory "image:$V1:retired" "image:$V2:active" "artifact:$ARTIFACT_KEY:active" >/dev/null
inventory_token_offline
snapshot_inventory 3

step "and now the document itself refuses: $V1 is already retired"
expect_fail "already listed as retired" "retiring $V1 after the inventory says so" -- retire "$V1"

step "the retired entry still says what was once valid"
python3 - "$KEYS/key-inventory.json" "$V1" "$KEYS/$V1.pub" "$WORK/history/key-inventory.v1.json" <<'PY'
import json, sys
current, label, pub_path, first = sys.argv[1:5]
entry = next(k for k in json.load(open(current))["keys"] if k["label"] == label)
assert entry["status"] == "retired", entry["status"]
assert entry["retired_at"], "retired without a retired_at"
assert entry["public_key"] == open(pub_path).read(), "public key differs from the one exported at provisioning"
original = next(k for k in json.load(open(first))["keys"] if k["label"] == label)
assert original["public_key"] == entry["public_key"], "public key differs from inventory version 1"
assert original["valid_from"] == entry["valid_from"], "valid_from was not carried over"
print(f"    ok: {label} is retired at {entry['retired_at']}; public key and valid_from carried from version 1")
PY

log "7/7  signing with $V1 is impossible, and what it signed no longer verifies"
step "the resolver refuses the label"
expect_fail "which the inventory does not list as the" "forcing the retired $V1 through the override" \
    -- env HSM_PKI_IMAGE_KEY_LABEL="$V1" "$REPO_ROOT/ci/sign-image.sh" "$AFTER_REF"

step "and the token no longer holds it, so cosign cannot sign with it either"
# Straight to cosign with the PKCS#11 URI, bypassing every script above.
# The private key is gone; no policy is involved in this refusal. The
# wording is cosign v2.6.1's for an object the token does not hold,
# measured: the same call with the next version's label succeeded a few
# steps ago, and the label is the only difference.
expect_fail "initializing pkcs11 token signer verifier: signer not set" "cosign sign with the destroyed $V1" \
    -- env HSM_PKI_COSIGN_VERSION=v2 HSM_PKI_COSIGN_NETWORK=host "$REPO_ROOT/ci/cosign.sh" sign \
        --key "pkcs11:token=$SUPPLY_TOKEN_LABEL;object=$V1" \
        --tlog-upload=false -y --allow-http-registry=true "$AFTER_REF"

step "before-roll no longer verifies: its only signature is by a retired key"
assert_equal "a verifier may accept only $V2 now" "$V2 active" "$(selection)"
expect_fail "no key in the verified inventory produced this image's signature" "before-roll under inventory version 3" \
    -- verify_release "$BEFORE_REF"

step "after-roll still verifies"
expect_line "signature +$V2\$" "after-roll under inventory version 3" -- verify_release "$AFTER_REF"

step "the policy renders one key, and an older inventory is refused as a rollback"
expect_line "1 trusted image key\(s\) from .* version 3" "policy from inventory version 3" \
    -- render_policy "$KEYS_REL/key-inventory.json"
expect_fail "refusing the rollback" "policy from inventory version 2 over the version-3 rendering" \
    -- render_policy "$WORK_REL/history/key-inventory.v2.json"

unset COSIGN_PKCS11_PIN

cat <<EOT

The image-signing key went through its whole lifecycle on a throwaway
token, and every signer and verifier followed the inventory:

  $V1   active -> verify-only -> retired (destroyed on the token)
  $V2   provisioned, took over signing at the roll
  inventory              version 1 -> 2 -> 3, each signed by the offline token

  before-roll  $BEFORE_REF
               verified under versions 1 and 2, refused under 3
  after-roll   $AFTER_REF
               verified under versions 2 and 3

  registry     $REGISTRY (removed now)
  keys         $KEYS_REL (ephemeral; not the published ones)
  history      $WORK_REL/history/
EOT
