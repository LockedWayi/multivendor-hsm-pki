#!/usr/bin/env bash
#
# Fetch, verify and run the PKCS#11-capable cosign.
#
#   ci/cosign.sh fetch            download and verify; idempotent
#   ci/cosign.sh <cosign args>    run it, in a container
#
# A signing tool is a supply-chain dependency of the thing it signs. A
# cosign binary an attacker chose reports every signature as valid, so
# obtaining it is itself a verification problem, and a circular one: the
# usual way to verify a Sigstore artifact is to run cosign.
#
# The circle is broken with the keyed bundle. Every cosign release asset
# carries two Sigstore bundles. <asset>-kms.sigstore.json is signed by the
# long-lived release key published as release-cosign.pub, so it is checked
# here with openssl and the copy of that key pinned in this repository
# (ci/sigstore-release-cosign.pub). The pinned key is byte-identical to the
# one published with cosign v1.13.0, v2.2.0 and v3.1.3.
#
# Three parties have to agree before the binary is used: GitHub serves the
# asset and lists its SHA-256 in cosign_checksums.txt; the Sigstore release
# key signs that digest; Rekor records that signature. And the digest is
# pinned in this script, so after the first review a changed byte is a
# failed comparison, not a re-run of the same fetch.
#
# Two tracks are pinned. cosign v3 stores an image signature as an OCI
# referrers artifact, and Kyverno v1.19's verifier looks for the older
# sha256-<digest>.sig tag, which is what cosign v2 writes. So images signed
# with the PKCS#11 key use v2, and everything else uses v3:
#
#   HSM_PKI_COSIGN_VERSION=v3   release artifacts and keyless signing (default)
#   HSM_PKI_COSIGN_VERSION=v2   PKCS#11 image signatures, for Kyverno
#
# cosign's PKCS#11 support is a build tag, so the asset name is part of the
# pin: the default cosign-linux-<arch> cannot load a module at all.
set -euo pipefail

# Two pinned versions, and the reason is measured rather than cautious.
#
# cosign v3 stores an image signature as an OCI referrers artifact, under the
# fallback tag `sha256-<digest>` when the registry has no referrers API.
# Kyverno v1.19's cosign verifier looks for the older `sha256-<digest>.sig`
# tag and reports "no signatures found" against a v3 signature that cosign
# itself verifies happily. There is no flag on either side that bridges it:
# v3 has no legacy-format option, and v1.19 is the current Kyverno.
#
# So blobs are signed with v3 (its bundle is what internal/artifactsig
# reads) and images with v2 (its layout is what admission reads), and both
# are pinned and verified the same way rather than one being trusted because
# the other was.
#
#   HSM_PKI_COSIGN_VERSION=v3   release artifacts   (default)
#   HSM_PKI_COSIGN_VERSION=v2   container images
#
# cosign's PKCS#11 support is a build tag, not a runtime flag, so the asset
# name is part of the pin: the default cosign-linux-<arch> is statically
# linked and cannot dlopen a module at all.
COSIGN_TRACK="${HSM_PKI_COSIGN_VERSION:-v3}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${HSM_PKI_COSIGN_DIR:-$REPO_ROOT/.local/bin}"
RELEASE_KEY="$REPO_ROOT/ci/sigstore-release-cosign.pub"
RUNNER_IMAGE="hsm-pki-cosign:local"

# Where deploy/docker/provision-signing-keys.sh left the tokens and the
# module. Overridable so a real deployment can point at its own.
STATE="${HSM_PKI_SIGNING_STATE:-$REPO_ROOT/.local/signing}"

REKOR_API="https://rekor.sigstore.dev/api/v1/log/entries"
REKOR_INDEX_API="https://rekor.sigstore.dev/api/v1/index/retrieve"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { echo "cosign.sh: $*" >&2; exit 1; }

# The digest is per architecture. The runner image's base is multi-arch, so
# an amd64 binary on an arm64 host fails with "exec format error". An
# unknown architecture is refused: cosign publishes the pivkey-pkcs11key
# asset for these two only.
case "$(uname -m)" in
    x86_64)        COSIGN_ARCH="amd64" ;;
    aarch64|arm64) COSIGN_ARCH="arm64" ;;
    *)
        die "no pinned cosign for architecture $(uname -m). cosign publishes
the PKCS#11-capable build for linux/amd64 and linux/arm64 only; adding one
means adding its digest here, verified the same way as the others." ;;
esac

# RELEASE_SIG_STYLE says where the release's own signature lives:
#   bundle    v3: <asset>-kms.sigstore.json, a keyed Sigstore bundle
#   detached  v2: <asset>.sig, base64 of the raw ECDSA signature
# Same release key either way; openssl checks both.
case "$COSIGN_TRACK" in
    v3)
        COSIGN_VERSION="v3.1.3"
        RELEASE_SIG_STYLE="bundle"
        case "$COSIGN_ARCH" in
            amd64) COSIGN_SHA256="549398fbe5a2f930b4eb564c7bbe9588270566ffcc8c9cb45644c066714aa380" ;;
            arm64) COSIGN_SHA256="43266ec58f867517ab60e46972a1700f72f277d4c62a039325a4af66e4a1a1e4" ;;
        esac ;;
    v2)
        COSIGN_VERSION="v2.6.1"
        RELEASE_SIG_STYLE="detached"
        case "$COSIGN_ARCH" in
            amd64) COSIGN_SHA256="cc616c0d689a1ce248de015db41a925eb4cb1fcd8f49349e4e884a3a3838e328" ;;
            arm64) COSIGN_SHA256="5d3fa7ef6c86156f33077ea953a97e147dfd57311eef9dabd7b0869bdf8db926" ;;
        esac ;;
    *)
        die "HSM_PKI_COSIGN_VERSION must be v3 (release artifacts) or v2 (container images), not \"$COSIGN_TRACK\"" ;;
esac
COSIGN_ASSET="cosign-linux-pivkey-pkcs11key-$COSIGN_ARCH"
# One binary per track, side by side, because the two are not
# interchangeable.
COSIGN_BIN="$BIN_DIR/cosign-$COSIGN_VERSION"
RELEASE_URL="https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION"

verify_pinned_digest() {
    local actual
    actual="$(sha256sum "$COSIGN_BIN" | cut -d' ' -f1)"
    [ "$actual" = "$COSIGN_SHA256" ] || die \
        "$COSIGN_BIN has SHA-256 $actual, expected $COSIGN_SHA256.
Delete it and re-run 'ci/cosign.sh fetch'. If a fresh download still
disagrees, the pin in this script and the published release have diverged:
that is a supply-chain event, not a stale cache. Do not update the pin to
match what arrived."
}

fetch() {
    mkdir -p "$BIN_DIR"
    local work
    work="$(mktemp -d)"
    # EXIT, not RETURN: a RETURN trap does not fire when die exits the
    # script. Double quotes, so the path is expanded now; work is
    # function-local and the trap runs after it is out of scope.
    trap "rm -rf '$work'" EXIT

    log "downloading $COSIGN_ASSET $COSIGN_VERSION"
    curl -sSL --fail -o "$work/cosign" "$RELEASE_URL/$COSIGN_ASSET"
    curl -sSL --fail -o "$work/checksums.txt" "$RELEASE_URL/cosign_checksums.txt"
    if [ "$RELEASE_SIG_STYLE" = "bundle" ]; then
        curl -sSL --fail -o "$work/bundle.json" "$RELEASE_URL/$COSIGN_ASSET-kms.sigstore.json"
    fi

    local digest
    digest="$(sha256sum "$work/cosign" | cut -d' ' -f1)"

    log "1/4  the digest matches the pin in this script"
    [ "$digest" = "$COSIGN_SHA256" ] || die \
        "downloaded $COSIGN_ASSET has SHA-256 $digest, but this script pins
$COSIGN_SHA256. Either the release was replaced or you are pointing at a
different version. Investigate before changing the pin."
    echo "    $digest"

    log "2/4  the digest matches the published checksums file"
    grep -q "^$digest  $COSIGN_ASSET\$" "$work/checksums.txt" || die \
        "cosign_checksums.txt does not list $digest for $COSIGN_ASSET"
    echo "    listed in cosign_checksums.txt"

    log "3/4  the Sigstore release key signed exactly these bytes"
    if [ "$RELEASE_SIG_STYLE" = "detached" ]; then
        # v2 publishes <asset>.sig: base64 of the DER ECDSA signature over
        # the artifact.
        curl -sSL --fail -o "$work/asset.sig.b64" "$RELEASE_URL/$COSIGN_ASSET.sig"
        base64 -d < "$work/asset.sig.b64" > "$work/sig.der"
        echo "    detached signature, checked against the pinned release key"
    else
        # The bundle's messageSignature is a raw ECDSA-SHA256 signature over
        # the artifact, which openssl dgst -verify checks. The bundle's
        # publicKey.hint is the base64 SHA-256 of the release key's DER
        # SubjectPublicKeyInfo, so a bundle signed by another key is
        # rejected as naming the wrong key. The Python below sits at column
        # 0 because it is a quoted heredoc.
        python3 - "$work/bundle.json" "$work/sig.der" "$RELEASE_KEY" <<'PY'
import base64, hashlib, json, sys
bundle_path, sig_path, key_path = sys.argv[1:4]
bundle = json.load(open(bundle_path))
material = bundle["verificationMaterial"]
if "certificate" in material:
    sys.exit("this is the keyless bundle (Fulcio certificate); "
             "the -kms bundle is the one this script verifies")
hint = material["publicKey"]["hint"]
pem = open(key_path).read()
der = base64.b64decode("".join(l for l in pem.splitlines() if not l.startswith("---")))
expected = base64.b64encode(hashlib.sha256(der).digest()).decode()
if hint != expected:
    sys.exit(f"bundle names key {hint}, pinned key is {expected}")
open(sig_path, "wb").write(base64.b64decode(bundle["messageSignature"]["signature"]))
print(f"    bundle names the pinned release key ({hint})")
PY
    fi
    openssl dgst -sha256 -verify "$RELEASE_KEY" \
        -signature "$work/sig.der" "$work/cosign" \
        || die "the release signature does not verify over the downloaded bytes"

    log "4/4  Rekor's public log records that signature"
    # The one check GitHub cannot answer for itself. If only this step
    # fails, the network is the likely cause, so it warns rather than dies.
    local located=1
    if [ "$RELEASE_SIG_STYLE" = "bundle" ]; then
        local log_index
        log_index="$(python3 -c '
import json,sys
print(json.load(open(sys.argv[1]))["verificationMaterial"]["tlogEntries"][0]["logIndex"])
' "$work/bundle.json")"
        curl -sS --fail --max-time 30 "$REKOR_API?logIndex=$log_index" -o "$work/rekor.json" || located=0
    else
        # No bundle, so Rekor's index is searched by the artifact's hash.
        local uuids
        uuids="$(curl -sS --fail --max-time 30 -X POST -H 'Content-Type: application/json' \
            -d "{\"hash\":\"sha256:$digest\"}" "$REKOR_INDEX_API" 2>/dev/null \
            | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin)))' 2>/dev/null || true)"
        if [ -n "$uuids" ]; then
            # Every entry, merged into one document: the check is "at least
            # one of these".
            : > "$work/entries.jsonl"
            while read -r u; do
                [ -n "$u" ] || continue
                curl -sS --fail --max-time 30 "$REKOR_API/$u" >> "$work/entries.jsonl" 2>/dev/null || true
                printf '\n' >> "$work/entries.jsonl"
            done <<< "$uuids"
            python3 -c '
import json,sys
merged={}
for line in open(sys.argv[1]):
    line=line.strip()
    if line:
        merged.update(json.loads(line))
json.dump(merged, open(sys.argv[2],"w"))' "$work/entries.jsonl" "$work/rekor.json" || located=0
        else
            located=0
        fi
    fi
    if [ "$located" = 1 ]; then
        assert_rekor_records "$work/rekor.json" "$digest"
    else
        echo "    WARNING: could not reach Rekor. The first three checks passed," >&2
        echo "    so the bytes are the ones the release key signed; what is" >&2
        echo "    unconfirmed is that the signature is publicly logged." >&2
    fi

    log "confirming this build actually has PKCS#11 support"
    # curl writes 0644, and a non-executable binary bind-mounted into the
    # runner fails at container init.
    chmod +x "$work/cosign"
    assert_pkcs11_build "$work/cosign"

    # Installed only after every check has passed.
    install -m 0755 "$work/cosign" "$COSIGN_BIN"

    log "ready: $COSIGN_BIN ($COSIGN_VERSION, $COSIGN_ASSET)"
}

# assert_rekor_records checks that Rekor's response records this digest
# under the pinned key. It is a function so ci/cosign-selftest.sh can drive
# it. Inline, a loop over an empty response checked nothing and returned
# success.
assert_rekor_records() {
    python3 - "$1" "$2" "$RELEASE_KEY" <<'PY'
import base64, json, sys
entries = json.load(open(sys.argv[1]))
digest, key_path = sys.argv[2], sys.argv[3]
pinned = open(key_path).read().strip()
if not entries:
    sys.exit("Rekor returned no entry, so nothing confirms the signature is "
             "publicly logged")

# At least one entry must record this digest under the pinned key. A cosign
# release is signed twice, once with the release key and once keyless, so
# requiring every entry to match rejected a good release.
matched = []
for uuid, entry in entries.items():
    spec = json.loads(base64.b64decode(entry["body"]))["spec"]
    if spec.get("data", {}).get("hash", {}).get("value") != digest:
        continue
    content = spec.get("signature", {}).get("publicKey", {}).get("content")
    if not content:
        continue
    if base64.b64decode(content).decode().strip() == pinned:
        matched.append(uuid)

if not matched:
    sys.exit(f"none of the {len(entries)} Rekor entries for this artifact "
             f"records digest {digest} under the pinned release key")
print(f"    entry {matched[0][:16]}... records this digest under the pinned "
      f"key ({len(matched)} of {len(entries)} entries)")
PY
}

# ensure_runner_image builds the runner image every time. An existence
# check returned a stale image after ci/cosign.Dockerfile changed. An
# unchanged rebuild costs about a second from the layer cache.
ensure_runner_image() {
    docker build -q -f "$REPO_ROOT/ci/cosign.Dockerfile" -t "$RUNNER_IMAGE" "$REPO_ROOT" >/dev/null
}

# assert_pkcs11_build confirms that the binary at $1 was built with the
# pkcs11key tag, by asking it to do something only that build attempts. An
# earlier version checked for the absence of the stub's refusal string and
# passed on a machine with no module at all, so this asserts a positive
# signal:
#
#   stub build  "This cosign was not built with pkcs11-tool support!", exit 0
#   real build  "failed to load PKCS11 module", exit 1, or a token listing
#
# Anything else fails closed.
assert_pkcs11_build() {
    local binary="$1" out
    ensure_runner_image
    # No signing-state mounts. Mounting a state directory that does not
    # exist yet makes docker create it on the host as root, which then
    # blocks deploy/docker/provision-signing-keys.sh.
    out="$(docker run --rm \
        -v "$binary":/usr/local/bin/cosign:ro \
        -e COSIGN_PKCS11_MODULE_PATH=/nonexistent/no-such-module.so \
        "$RUNNER_IMAGE" pkcs11-tool list-tokens 2>&1 || true)"
    case "$out" in
        *"not built with pkcs11-tool support"*)
            die "this binary is the stub build: it has no PKCS#11 support.
The default cosign-linux-amd64 answers pkcs11 subcommands this way and
exits 0, so the asset name is part of the pin, not a convenience." ;;
        *"failed to load PKCS11 module"*|*"Listing tokens of PKCS11 module"*)
            echo "    pkcs11-tool tried to load a module, so the tag is present" ;;
        *)
            die "could not confirm PKCS#11 support. cosign said:
$out" ;;
    esac
}

run() {
    [ -x "$COSIGN_BIN" ] || die "no cosign at $COSIGN_BIN. Run: ci/cosign.sh fetch"
    verify_pinned_digest

    # Verification mounts no token. The decision is taken from the
    # subcommand, not from a flag: there is no argument to this script that
    # both verifies and reaches a private key.
    local verify_only=0
    case "${1:-}" in
        verify|verify-blob|verify-attestation) verify_only=1 ;;
    esac

    if [ "$verify_only" = "1" ]; then
        for arg in "$@"; do
            case "$arg" in
                pkcs11:*) die \
                    "refusing to verify with a PKCS#11 key.
Verification here runs with no token mounted. A verifier that can reach a
private key is not independent. Pass a published public key instead." ;;
            esac
        done
        ensure_runner_image

        local vnet_args=()
        [ -n "${HSM_PKI_COSIGN_NETWORK:-}" ] && vnet_args=(--network "$HSM_PKI_COSIGN_NETWORK")
        local vcred_args=()
        if [ -n "${HSM_PKI_DOCKER_CONFIG:-}" ]; then
            vcred_args=(-v "${HSM_PKI_DOCKER_CONFIG}":/dockerconfig:ro
                        -e DOCKER_CONFIG=/dockerconfig)
        fi

        # No token store, no module, no SOFTHSM2_CONF, no PIN.
        docker run --rm -i \
            "${vnet_args[@]}" \
            "${vcred_args[@]}" \
            -v "$COSIGN_BIN":/usr/local/bin/cosign:ro \
            -v "$REPO_ROOT":/repo -w /repo \
            "$RUNNER_IMAGE" "$@"
        return
    fi

    # Keyless mode: no token, no module, no PIN. The identity comes from
    # the runner's OIDC token, which cosign requests itself through the
    # ACTIONS_ID_TOKEN_REQUEST_* variables passed in here. Fulcio, Rekor
    # and the TUF root are reached over the container's own network.
    if [ "${HSM_PKI_COSIGN_MODE:-}" = "keyless" ]; then
        for arg in "$@"; do
            case "$arg" in
                pkcs11:*) die "refusing a PKCS#11 key in keyless mode. Unset HSM_PKI_COSIGN_MODE to sign with a token." ;;
            esac
        done
        [ -z "${COSIGN_PKCS11_PIN:-}" ] || die \
            "COSIGN_PKCS11_PIN is set in keyless mode. A keyless signing step holds no PIN."
        ensure_runner_image
        local knet_args=() kcred_args=() oidc_args=()
        [ -n "${HSM_PKI_COSIGN_NETWORK:-}" ] && knet_args=(--network "$HSM_PKI_COSIGN_NETWORK")
        if [ -n "${HSM_PKI_DOCKER_CONFIG:-}" ]; then
            kcred_args=(-v "${HSM_PKI_DOCKER_CONFIG}":/dockerconfig:ro
                        -e DOCKER_CONFIG=/dockerconfig)
        fi
        local v
        for v in ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN SIGSTORE_ID_TOKEN; do
            [ -n "${!v:-}" ] && oidc_args+=(-e "$v")
        done
        docker run --rm -i \
            "${knet_args[@]}" \
            "${kcred_args[@]}" \
            "${oidc_args[@]}" \
            -v "$COSIGN_BIN":/usr/local/bin/cosign:ro \
            -v "$REPO_ROOT":/repo -w /repo \
            "$RUNNER_IMAGE" "$@"
        return
    fi

    # Checked here rather than left to docker, which would create each
    # missing path on the host as a root-owned directory, and
    # provision-signing-keys.sh then refuses to run over it.
    local missing=()
    [ -d "$STATE/pkcs11" ] || missing+=("$STATE/pkcs11")
    [ -d "$STATE/tokens" ] || missing+=("$STATE/tokens")
    [ -d "$STATE/etc" ]    || missing+=("$STATE/etc")
    if [ ${#missing[@]} -gt 0 ]; then
        die "no signing state to work with. Missing:
$(printf '  %s\n' "${missing[@]}")
Provision the keys first:  deploy/docker/provision-signing-keys.sh
(or point HSM_PKI_SIGNING_STATE at an existing store)."
    fi
    ensure_runner_image

    # The PIN reaches cosign as an environment variable, never inside the
    # PKCS#11 URI: a URI is a command-line argument and reaches ps output.
    local pin_args=()
    if [ -n "${COSIGN_PKCS11_PIN:-}" ]; then
        pin_args=(-e COSIGN_PKCS11_PIN)
    fi

    # Image signing has to reach a registry; blob signing must not. The
    # network is opt-in per invocation.
    local net_args=()
    if [ -n "${HSM_PKI_COSIGN_NETWORK:-}" ]; then
        net_args=(--network "$HSM_PKI_COSIGN_NETWORK")
    fi

    # Registry credentials, opt-in per invocation and read-only. cosign
    # reads them from a docker config directory; without one it is
    # anonymous and a private registry answers with an authentication
    # error.
    local cred_args=()
    if [ -n "${HSM_PKI_DOCKER_CONFIG:-}" ]; then
        [ -d "${HSM_PKI_DOCKER_CONFIG}" ] || die \
            "HSM_PKI_DOCKER_CONFIG=${HSM_PKI_DOCKER_CONFIG} is not a directory.
DOCKER_CONFIG names the directory holding config.json, not the file."
        cred_args=(-v "${HSM_PKI_DOCKER_CONFIG}":/dockerconfig:ro
                   -e DOCKER_CONFIG=/dockerconfig)
    fi

    docker run --rm -i \
        "${net_args[@]}" \
        "${cred_args[@]}" \
        -v "$COSIGN_BIN":/usr/local/bin/cosign:ro \
        -v "$REPO_ROOT":/repo -w /repo \
        -v "$STATE/tokens":/var/lib/softhsm/tokens \
        -v "$STATE/pkcs11":/pkcs11:ro \
        -v "$STATE/etc":/conf:ro \
        -e SOFTHSM2_CONF=/conf/softhsm2.conf \
        -e COSIGN_PKCS11_MODULE_PATH=/pkcs11/libsofthsm2.so \
        "${pin_args[@]}" \
        "$RUNNER_IMAGE" "$@"
}

# Guarded so ci/cosign-selftest.sh can source this file and exercise the
# individual checks.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        fetch) shift; fetch "$@" ;;
        "")    die "usage: ci/cosign.sh fetch | ci/cosign.sh <cosign args>" ;;
        *)     run "$@" ;;
    esac
fi
