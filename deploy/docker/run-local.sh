#!/usr/bin/env bash
#
# Run the CA service locally, end to end, with no HSM hardware and no
# proprietary SDK -- one command, from a clean checkout.
#
# This script exists because of a decision and its cost. No PKCS#11 module
# ships in the service image (docs/phases/phase-4-container-k8s.md, "Decide
# before starting"), which keeps the published artifact free of any key
# store but also means the image cannot start on its own. CLAUDE.md §1 says
# any reader must be able to reproduce this repository without hardware, so
# the burden that left the image lands here instead of on the reader.
#
# What it does, in order:
#   1. builds the service image and the SoftHSM2 dev image
#   2. initializes two SoftHSM2 tokens -- a root and an intermediate
#   3. runs the offline root ceremony against them (cmd/hsm-pki-keytool)
#   4. moves the root token out of the store the service can reach
#   5. starts the service, read-only and non-root, against what is left
#
# Step 4 is the one to read twice. The two-tier hierarchy's guarantee is
# that a compromised service cannot reach the root, and on real hardware
# that is a token in a safe. Here it is a directory moved out of the
# token store before the service ever starts, so the same guarantee holds
# for the same reason rather than by assertion: the root's token is not in
# the filesystem the service is given.
#
# Usage:
#   deploy/docker/run-local.sh          start (creates state on first run)
#   deploy/docker/run-local.sh --reset  destroy the local state and start over
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="${HSM_PKI_LOCAL_STATE:-$REPO_ROOT/.local/dev}"
SERVICE_IMAGE="hsm-pki-server:local"
DEV_IMAGE="hsm-pki-dev:local"
PORT="${HSM_PKI_LOCAL_PORT:-8080}"

# Throwaway PINs for a throwaway local token. They are passed to the
# containers as environment variables and never written into config.yaml,
# which holds only the NAME of the variable to read (CLAUDE.md §3.1, §3.2).
# Nothing here is a secret worth protecting; the point is that the
# mechanism is the same one a real deployment uses.
ROOT_PIN="1234"
INTERMEDIATE_PIN="1234"

ROOT_TOKEN_LABEL="hsm-pki-local-root"
INTERMEDIATE_TOKEN_LABEL="hsm-pki-local-intermediate"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if [[ "${1:-}" == "--reset" ]]; then
    log "removing local state at $STATE"
    # The state directory is written by containers running as other UIDs,
    # so the removal runs as root in a container too rather than asking the
    # reader for sudo on their own machine.
    if [[ -d "$STATE" ]]; then
        docker run --rm -v "$(dirname "$STATE")":/parent alpine:3 \
            rm -rf "/parent/$(basename "$STATE")"
    fi
    shift
fi

if [[ -d "$STATE" ]]; then
    log "reusing existing local state at $STATE (--reset to start over)"
    SETUP_DONE=1
else
    SETUP_DONE=0
fi

log "building images"
docker build -q -f "$REPO_ROOT/deploy/docker/Dockerfile" -t "$SERVICE_IMAGE" "$REPO_ROOT"
docker build -q -f "$REPO_ROOT/ci/softhsm2-dev.Dockerfile" -t "$DEV_IMAGE" "$REPO_ROOT"

if [[ "$SETUP_DONE" == "0" ]]; then
    mkdir -p "$STATE"/{pkcs11,etc,tokens,var,offline-root-token}

    log "extracting the SoftHSM2 module"
    # Copied out of the dev image rather than mounted from the host, so this
    # works on a machine with no softhsm2 installed. The path inside the
    # image is the real object, not Debian's /usr/lib/softhsm symlink: a
    # mount of the symlink reproduces a dangling link inside the container,
    # which fails exactly like a missing module.
    cid="$(docker create "$DEV_IMAGE" /bin/true)"
    docker cp "$cid:/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" "$STATE/pkcs11/libsofthsm2.so"
    docker rm -f "$cid" >/dev/null

    cat > "$STATE/etc/softhsm2.conf" <<EOF
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = ERROR
EOF

    log "initializing two tokens: $ROOT_TOKEN_LABEL and $INTERMEDIATE_TOKEN_LABEL"
    # Two tokens, not two labels on one token. The ceremony refuses to put
    # the root and the intermediate on the same token, and compares serial
    # numbers rather than labels to decide (CLAUDE.md §3.8).
    docker run --rm \
        -v "$STATE/tokens":/var/lib/softhsm/tokens \
        -v "$STATE/etc":/conf:ro \
        -e SOFTHSM2_CONF=/conf/softhsm2.conf \
        "$DEV_IMAGE" sh -c "
            softhsm2-util --init-token --free --label '$ROOT_TOKEN_LABEL' \
                --so-pin '$ROOT_PIN' --pin '$ROOT_PIN' >/dev/null
            softhsm2-util --init-token --free --label '$INTERMEDIATE_TOKEN_LABEL' \
                --so-pin '$INTERMEDIATE_PIN' --pin '$INTERMEDIATE_PIN' >/dev/null
            softhsm2-util --show-slots | grep -E 'Label:|Serial'
        "

    log "running the offline root ceremony"
    # cmd/hsm-pki-keytool is not in the service image and never will be --
    # it is the one binary here that can reach a root token. It runs from
    # the dev image, which is the local stand-in for an operator's offline
    # workstation.
    docker run --rm \
        -v "$REPO_ROOT":/repo -w /repo \
        -v "$STATE/tokens":/var/lib/softhsm/tokens \
        -v "$STATE/pkcs11":/pkcs11:ro \
        -v "$STATE/etc":/artifacts \
        -e SOFTHSM2_CONF=/artifacts/softhsm2.conf \
        -e HSM_PKI_ROOT_PIN="$ROOT_PIN" \
        -e HSM_PKI_INTERMEDIATE_PIN="$INTERMEDIATE_PIN" \
        "$DEV_IMAGE" sh -c "
            git config --global --add safe.directory /repo
            go run ./cmd/hsm-pki-keytool ceremony \
                -module /pkcs11/libsofthsm2.so \
                -root-workspace '$ROOT_TOKEN_LABEL' \
                -root-pin-env HSM_PKI_ROOT_PIN \
                -root-key-label ca-root-key-v1 \
                -root-cert-out /artifacts/root.pem \
                -root-crl-out /artifacts/root-crl.pem \
                -root-cert-url 'http://localhost:$PORT/root.crt' \
                -root-crl-url 'http://localhost:$PORT/root.crl' \
                -intermediate-workspace '$INTERMEDIATE_TOKEN_LABEL' \
                -intermediate-pin-env HSM_PKI_INTERMEDIATE_PIN \
                -intermediate-key-label ca-intermediate-key-v1 \
                -intermediate-cert-out /artifacts/intermediate.pem
        "

    log "taking the root token offline"
    # Identify the root's token directory by the label stored in it, and
    # refuse to act on anything but exactly one match. Resolving an
    # ambiguous match to the first hit would let enumeration order decide
    # which token goes in the safe, which is nobody's decision
    # (CLAUDE.md §3.8).
    #
    # This runs in a container rather than on the host because SoftHSM2
    # creates each token directory mode 0700 owned by the user that
    # initialized it -- root, here. A host-side search reads none of them
    # and, if its errors are suppressed, reports "no match" for a token
    # that is plainly there. Found the hard way: the first version of this
    # script did exactly that and moved nothing.
    docker run --rm -v "$STATE":/state -e ROOT_LABEL="$ROOT_TOKEN_LABEL" "$DEV_IMAGE" sh -c '
        set -eu
        matches=$(grep -rla -- "$ROOT_LABEL" /state/tokens | xargs -r -n1 dirname | sort -u)
        count=$(printf "%s" "$matches" | grep -c . || true)
        if [ "$count" -ne 1 ]; then
            echo "expected exactly one token directory holding $ROOT_LABEL, found $count" >&2
            printf "  %s\n" $matches >&2
            exit 1
        fi
        mv "$matches" /state/offline-root-token/
        echo "root token directory $(basename "$matches") moved out of the store"
    '
    echo "the service is never given $STATE/offline-root-token"

    log "writing config.yaml"
    # No PIN in this file, by design: pin_env names the variable the PIN is
    # read from at startup, so a leaked config.yaml leaks nothing.
    cat > "$STATE/etc/config.yaml" <<EOF
server:
  listen_addr: "0.0.0.0:$PORT"

pkcs11:
  adapter: "softhsm2"
  session:
    idle_timeout: "15m"
    max_ttl: "8h"
  softhsm2:
    module_path: "/pkcs11/libsofthsm2.so"
    workspace_label: "$INTERMEDIATE_TOKEN_LABEL"
    pin_env: "HSM_PKI_INTERMEDIATE_PIN"

ca:
  curve: "P-256"
  cert_ttl_hours: 8760
  intermediate_key_label: "ca-intermediate-key-v1"
  intermediate_cert_path: "/etc/hsm-pki/intermediate.pem"
  root_cert_path: "/etc/hsm-pki/root.pem"
  root_crl_path: "/etc/hsm-pki/root-crl.pem"
  base_url: "http://localhost:$PORT"
  crl_validity_hours: 24
  store_path: "/var/lib/hsm-pki/ca.db"
EOF

    log "handing the writable paths to the service's UID"
    # The service runs as 65532 and the container that created these
    # directories ran as root. Done in a container so the reader never
    # needs sudo on their own machine. In Kubernetes this is fsGroup on the
    # pod's security context instead (4.4), not a chown.
    docker run --rm -v "$STATE":/state "$DEV_IMAGE" \
        chown -R 65532:65532 /state/tokens /state/var
fi

log "starting the service"
cat <<EOF
  read-only root filesystem, non-root UID, no shell in the image.
  Writable state is explicit: the token store and the CA database, nothing else.

  Try:
    curl -s localhost:$PORT/healthz
    curl -s localhost:$PORT/readyz
    curl -sI localhost:$PORT/root.crt
    curl -s localhost:$PORT/root.crl | openssl crl -inform DER -noout -text | head

  Ctrl-C to stop.
EOF

# Interactive only when there is a terminal to be interactive with. `-it`
# against a redirected stdin fails outright, which would make this script
# unusable from CI or any non-interactive shell.
TTY_FLAGS=()
if [[ -t 0 && -t 1 ]]; then
    TTY_FLAGS=(-it)
fi

exec docker run --rm "${TTY_FLAGS[@]}" \
    --name hsm-pki-local \
    --read-only \
    --user 65532:65532 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    -p "$PORT:$PORT" \
    -v "$STATE/pkcs11":/pkcs11:ro \
    -v "$STATE/etc":/etc/hsm-pki:ro \
    -v "$STATE/tokens":/var/lib/softhsm/tokens \
    -v "$STATE/var":/var/lib/hsm-pki \
    -e SOFTHSM2_CONF=/etc/hsm-pki/softhsm2.conf \
    -e HSM_PKI_INTERMEDIATE_PIN="$INTERMEDIATE_PIN" \
    "$SERVICE_IMAGE"
