#!/usr/bin/env bash
#
# Fetch, verify and run the PKCS#11-capable cosign (Phase 4.9).
#
#   ci/cosign.sh fetch            download and verify; idempotent
#   ci/cosign.sh <cosign args>    run it against the local signing tokens
#
# Everything below exists because a signing tool is a supply-chain
# dependency of the thing it signs. A cosign binary that an attacker chose
# is a cosign binary that reports every signature as valid, so obtaining it
# is itself a verification problem -- and a circular one, since the usual
# way to verify a Sigstore artifact is to run cosign.
#
# The circle is broken with a keyed bundle rather than the keyless one.
# Every release asset carries two Sigstore bundles: <asset>.sigstore.json,
# signed by an ephemeral Fulcio certificate (checking it needs Sigstore's
# TUF trust root, which is one more thing to bootstrap), and
# <asset>-kms.sigstore.json, signed by the long-lived release key published
# as release-cosign.pub. The second needs nothing but that public key and an
# ECDSA verifier, so it is checked here with openssl -- an implementation
# that is not cosign and did not produce the signature.
#
# Three independent parties have to agree before the binary is used:
#
#   1. GitHub serves the asset and lists its SHA-256 in cosign_checksums.txt.
#   2. The Sigstore release key signs that same digest. Its public half is
#      pinned in this repository (ci/sigstore-release-cosign.pub) rather
#      than downloaded beside the thing it authenticates -- an anchor
#      fetched from the artifact's own source authenticates nothing. The
#      pinned key is byte-identical to the one published with cosign
#      v1.13.0 (2022), v2.2.0 (2023) and v3.1.3, and to the copy in the
#      cosign source tree, so substituting it means having substituted it
#      for four years.
#   3. Rekor, the public transparency log, holds an entry recording that
#      this digest was signed by that key at a stated time. That is the
#      party GitHub cannot silently overrule: a targeted binary served to
#      one user would have to be in a public, append-only log to verify.
#
# And the digest below is pinned in git, so after the first review none of
# the above is trusted again -- a changed byte is a failed comparison
# against a value a human approved, not a re-run of the same fetch.
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

# The digest is per architecture, so the architecture has to be resolved
# before there is anything to pin against. The runner image's base is a
# multi-arch manifest list, so on an arm64 host docker pulls an arm64
# runtime -- and an amd64 binary mounted into it fails with `exec format
# error`. Hardcoding amd64 would have made that the failure a reader on an
# Apple Silicon machine meets first.
#
# An unknown architecture is refused rather than guessed at: cosign publishes
# a pivkey-pkcs11key asset for exactly these two, and picking the wrong one
# produces a binary that cannot run, which is a worse outcome than being told
# so.
case "$(uname -m)" in
    x86_64)        COSIGN_ARCH="amd64" ;;
    aarch64|arm64) COSIGN_ARCH="arm64" ;;
    *)
        die "no pinned cosign for architecture $(uname -m). cosign publishes
the PKCS#11-capable build for linux/amd64 and linux/arm64 only; adding one
means adding its digest here, verified the same way as the others." ;;
esac

# RELEASE_SIG_STYLE says where the release's own signature lives, which
# differs between the two tracks and is the one thing the verification below
# cannot share:
#   bundle    v3: <asset>-kms.sigstore.json, a keyed Sigstore bundle
#   detached  v2: <asset>.sig, base64 of the raw ECDSA signature
# Same release key either way, and openssl checks both.
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
# One binary per track, side by side. A single path would mean the last
# fetch decides which version every later command runs, and the two are not
# interchangeable -- that is the whole reason both are pinned.
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
    # EXIT, not RETURN: a RETURN trap does not fire when die() exits the
    # script, which is every failure path here -- measured, and it left the
    # rejected 140 MB download behind each time. A verification that fails
    # must not leave its subject lying around.
    #
    # Double quotes so the path is expanded now rather than at exit: `work`
    # is function-local, so a trap deferring the expansion runs after it is
    # out of scope and dies on `set -u` -- which also skips the removal it
    # was there to do. Measured, not reasoned about.
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
        # the artifact, and nothing else. Fewer moving parts than the bundle
        # and the same question answered by the same key.
        curl -sSL --fail -o "$work/asset.sig.b64" "$RELEASE_URL/$COSIGN_ASSET.sig"
        base64 -d < "$work/asset.sig.b64" > "$work/sig.der"
        echo "    detached signature, checked against the pinned release key"
    else
        # The bundle's messageSignature is a raw ECDSA-SHA256 signature over
        # the artifact, which is what `openssl dgst -verify` checks -- so
        # this needs no Sigstore tooling and no network trust beyond the
        # pinned key. The bundle's publicKey.hint is checked too: it is the
        # base64 SHA-256 of the release key's DER SubjectPublicKeyInfo, so a
        # bundle signed by some other key is rejected as naming the wrong
        # key rather than as a signature mismatch, which is a clearer
        # failure.
        #
        # The Python below sits at column 0 and has to: this is a quoted
        # heredoc, so its body and its PY terminator are taken literally.
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
    # The one check GitHub cannot answer for itself. If this step is the
    # only one that fails the network is the likely cause, not an attack --
    # so it warns rather than dies, and says which it is.
    local located=1
    if [ "$RELEASE_SIG_STYLE" = "bundle" ]; then
        local log_index
        log_index="$(python3 -c '
import json,sys
print(json.load(open(sys.argv[1]))["verificationMaterial"]["tlogEntries"][0]["logIndex"])
' "$work/bundle.json")"
        curl -sS --fail --max-time 30 "$REKOR_API?logIndex=$log_index" -o "$work/rekor.json" || located=0
    else
        # No bundle, so no log index to follow. Rekor's index is searchable
        # by the artifact's hash instead, which reaches the same entries
        # from the other end and keeps this check the same check.
        local uuids
        uuids="$(curl -sS --fail --max-time 30 -X POST -H 'Content-Type: application/json' \
            -d "{\"hash\":\"sha256:$digest\"}" "$REKOR_INDEX_API" 2>/dev/null \
            | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin)))' 2>/dev/null || true)"
        if [ -n "$uuids" ]; then
            # Every entry the index knows about, merged into one document,
            # because the check below is "at least one of these" and taking
            # only the first makes the answer depend on Rekor's ordering.
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
    # runner fails with "permission denied" at container init. Found by the
    # positive probe below on its first run: the previous version of that
    # check swallowed this and reported PKCS#11 support anyway.
    chmod +x "$work/cosign"
    assert_pkcs11_build "$work/cosign"

    # Installed only after every check has passed, so a binary that fails one
    # never reaches the path the rest of this repository invokes.
    install -m 0755 "$work/cosign" "$COSIGN_BIN"

    log "ready: $COSIGN_BIN ($COSIGN_VERSION, $COSIGN_ASSET)"
}

# assert_rekor_records checks that Rekor's response for this log index
# really records this digest under the pinned key.
#
# Extracted from fetch so it can be driven directly by
# ci/cosign-selftest.sh. It was inline, and inline it hid a fail-open: a
# loop over an empty response checks nothing and returns success, so a valid
# but empty JSON object read as confirmation that the signature is publicly
# logged. A guard nobody can point a test at is a guard nobody has seen work.
assert_rekor_records() {
    python3 - "$1" "$2" "$RELEASE_KEY" <<'PY'
import base64, json, sys
entries = json.load(open(sys.argv[1]))
digest, key_path = sys.argv[2], sys.argv[3]
pinned = open(key_path).read().strip()
if not entries:
    sys.exit("Rekor returned no entry, so nothing confirms the signature is "
             "publicly logged")

# At least one entry must record this digest under the pinned key -- not
# every entry. Rekor's index returns everything logged for an artifact, and
# a cosign release is signed twice: once with the release key and once
# keylessly. Requiring all of them to match rejected a perfectly good
# release because the keyless entry, correctly, names a different key.
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

# ensure_runner_image makes sure the runner matches ci/cosign.Dockerfile.
#
# Called from both entry points, because they each need it and neither can
# assume the other ran first: on a fresh checkout `fetch` reached its last
# check with no image to run and failed there -- fail-closed, but the script
# was unusable on exactly the machine this project’s priority cares most about.
ensure_runner_image() {
    # Built every time rather than skipped when the tag exists. Measured: an
    # existence check returns a *stale* image after ci/cosign.Dockerfile
    # changes -- adding a package to it and re-running left the old image in
    # place, so the signing environment silently stopped matching the file
    # that is supposed to define it. Docker's layer cache makes an unchanged
    # rebuild cost about a second, which is the whole price of removing that
    # class of bug. (Alternative: stamp the image with a label carrying the
    # Dockerfile's digest and compare. Correct, and it saves the second, but
    # it is a second source of truth about when a rebuild is needed.)
    docker build -q -f "$REPO_ROOT/ci/cosign.Dockerfile" -t "$RUNNER_IMAGE" "$REPO_ROOT" >/dev/null
}

# assert_pkcs11_build confirms that the binary at $1 was built with the
# pkcs11key tag, by asking it to do something only that build can attempt.
#
# The first version of this checked for the *absence* of the stub build's
# refusal string and reported success otherwise -- which passed on a machine
# with no PKCS#11 module at all, printing a claim it had not measured. That
# is the same fail-open shape the check exists to defend against, so it now
# asserts a positive signal instead: the two builds are distinguishable by
# what they say when there is no module to load.
#
#   stub build  "This cosign was not built with pkcs11-tool support!", exit 0
#   real build  "failed to load PKCS11 module", exit 1  (or a token listing,
#               when a module happens to be present)
#
# Anything else -- a docker failure, a changed message in a future release --
# is unrecognised and fails closed rather than being read as a pass.
assert_pkcs11_build() {
    local binary="$1" out
    ensure_runner_image
    # Deliberately no signing-state mounts. Loading a module is not what is
    # being tested, and mounting a state directory that does not exist yet
    # makes docker create it on the host as root -- which then blocks
    # deploy/docker/provision-signing-keys.sh with "signing state already
    # exists" over directories this script invented.
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

    # Checked here rather than left to docker, which would create each
    # missing path on the host as a root-owned directory. That is not just
    # untidy: provision-signing-keys.sh refuses to run when its state
    # directory exists, so an invented one blocks key provisioning with
    # "signing state already exists" and advises --reset over state that was
    # never provisioned. Fail closed, and say what to run.
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

    # The PIN reaches cosign as an environment variable and never as
    # pin-value= in the PKCS#11 URI: a URI is a command-line argument, so it
    # lands in ps output, shell history and any log that echoes the command
    #
    local pin_args=()
    if [ -n "${COSIGN_PKCS11_PIN:-}" ]; then
        pin_args=(-e COSIGN_PKCS11_PIN)
    fi

    # Image signing has to reach a registry, and blob signing must not. So
    # the network is opt-in per invocation rather than always on: with no
    # HSM_PKI_COSIGN_NETWORK set, the signer runs with docker's default
    # bridge and cannot see the host's registry at all. ci/sign-image.sh
    # sets it; ci/sign-artifact.sh does not.
    local net_args=()
    if [ -n "${HSM_PKI_COSIGN_NETWORK:-}" ]; then
        net_args=(--network "$HSM_PKI_COSIGN_NETWORK")
    fi

    # Registry credentials, for the invocations that reach an authenticated
    # registry. cosign reads them from a docker config directory, and the
    # caller's lives outside the repository -- so with nothing mounted here
    # cosign is simply anonymous, and against a private registry that
    # surfaces as an authentication error from a step whose subject is
    # signing, which sends the reader to the key.
    #
    # Opt-in per invocation for the same reason the network is: a blob
    # signing run has no registry to reach, and a container that cannot
    # read a credential cannot leak one. Read-only, and the directory
    # rather than the file, because that is what DOCKER_CONFIG names.
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
# individual checks. A guard nobody can trigger deliberately is a guard
# nobody has seen work (the same reasoning as 4.8's lateral tests).
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        fetch) shift; fetch "$@" ;;
        "")    die "usage: ci/cosign.sh fetch | ci/cosign.sh <cosign args>" ;;
        *)     run "$@" ;;
    esac
fi
