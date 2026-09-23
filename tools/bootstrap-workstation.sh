#!/usr/bin/env bash
#
# Bring a fresh workstation to the state every script in this repository
# assumes, and prove it got there:
#
#   tools/bootstrap-workstation.sh [--no-smoke] [--with-protectserver]
#
# Four steps. Check the tools. Build the dev image. Run the whole suite
# against SoftHSM2 inside it. Bring the local deployment up once, query its
# public surface, and take it down again (--no-smoke skips that last step).
# Nothing is installed on the host: a missing tool is reported with what it
# is for, and the script stops there.
#
# --with-protectserver also runs the suite against a ProtectToolkit-C
# emulator on this host, which needs the seven PROTECTSERVER_* variables
# docs/test-matrix.md section 6 lists. With any of them unset the flag is
# refused rather than quietly reduced to SoftHSM2: a run that silently
# skipped the vendor backend is the run this repository's own history warns
# about.
#
# What this does not do: install a vendor client or SDK. Those come from
# the operator's own entitlement, and docs/test-matrix.md section 5 says
# what each backend must provide before it can join the rotation.
#
# Every step's full output lands under .local/bootstrap/, and the summary
# at the end reports the per-backend subtest counts the test matrix
# measures, with the same anchored pattern, so the number here and the
# number there are the same number.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$REPO_ROOT/.local/bootstrap"
DEV_IMAGE="hsm-pki-dev"
PORT="${HSM_PKI_LOCAL_PORT:-8080}"
PROTECTSERVER_SDK_DIR="${PROTECTSERVER_SDK_DIR:-/opt/safenet}"

SMOKE=1
WITH_PROTECTSERVER=0
for arg in "$@"; do
    case "$arg" in
        --no-smoke) SMOKE=0 ;;
        --with-protectserver) WITH_PROTECTSERVER=1 ;;
        -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "bootstrap-workstation: unknown argument $arg" >&2; exit 2 ;;
    esac
done

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
fail() { echo "bootstrap-workstation: $*" >&2; exit 1; }

mkdir -p "$LOG_DIR"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
log "1/4  tools"
# Required: what every script under ci/, deploy/ and tools/ calls. Optional:
# what only some paths need, reported so the operator knows what a later
# step will ask for.
missing=0
need() {
    local tool="$1" why="$2"
    if command -v "$tool" >/dev/null 2>&1; then
        printf '    %-10s ok\n' "$tool"
    else
        printf '    %-10s MISSING  (%s)\n' "$tool" "$why"
        missing=1
    fi
}
optional() {
    local tool="$1" why="$2"
    if command -v "$tool" >/dev/null 2>&1; then
        printf '    %-10s ok\n' "$tool"
    else
        printf '    %-10s absent   (%s)\n' "$tool" "$why"
    fi
}
need docker  "builds and runs every image; the suite and the service run inside it"
need git     "the lint gate and the scripts read the tracked file list from it"
need curl    "the smoke step and the verification recipes query the service"
need openssl "parses what the service serves and checks signatures independently"
optional gh      "opening pull requests and reading checks from the terminal"
optional k3d     "deploy/k8s/overlays/dev/k3d-up.sh, the local Kubernetes cluster"
optional kubectl "applying the Kubernetes overlay"
optional tofu    "ci/terraform-scan.sh and the infrastructure modules"
optional gpg     "the maintainer's encrypted state bundle, if one is being imported"
[ "$missing" -eq 0 ] || fail "install the missing tools above, then re-run"
docker info >/dev/null 2>&1 || fail "docker is installed but the daemon is not reachable by this user"

if [ "$WITH_PROTECTSERVER" -eq 1 ]; then
    for v in PROTECTSERVER_MODULE PROTECTSERVER_WORKSPACE PROTECTSERVER_PIN \
             PROTECTSERVER_ROOT_WORKSPACE PROTECTSERVER_INTERMEDIATE_WORKSPACE \
             PROTECTSERVER_ROOT_PIN PROTECTSERVER_INTERMEDIATE_PIN; do
        [ -n "${!v:-}" ] || fail "--with-protectserver needs $v set (docs/test-matrix.md, section 6, lists all seven)"
    done
    [ -d "$PROTECTSERVER_SDK_DIR" ] || fail "PROTECTSERVER_SDK_DIR=$PROTECTSERVER_SDK_DIR does not exist"
    [ -d "$HOME/.cryptoki" ] || fail "$HOME/.cryptoki (the emulator's token store) does not exist"
    echo "    ProtectServer: module $PROTECTSERVER_MODULE, SDK $PROTECTSERVER_SDK_DIR, store $HOME/.cryptoki"
fi

# ---------------------------------------------------------------------------
log "2/4  the dev image"
# One build, two tags: CONTRIBUTING's commands say hsm-pki-dev, run-local
# and the provisioning script say hsm-pki-dev:local. The Dockerfile is
# pinned by digest, so this is the same toolchain the pipeline runs.
docker build -f ci/softhsm2-dev.Dockerfile -t "$DEV_IMAGE" -t "$DEV_IMAGE:local" . \
    > "$LOG_DIR/build.log" 2>&1 || { tail -20 "$LOG_DIR/build.log"; fail "image build failed (full log: $LOG_DIR/build.log)"; }
docker image inspect --format '    {{.RepoTags}} {{.Size}} bytes' "$DEV_IMAGE"

# ---------------------------------------------------------------------------
log "3/4  the suite, -race -p 1, inside the image"
# -p 1 is not optional: several package test binaries would otherwise open
# the same token store at once. The vendor mounts are added only with the
# flag, so a run without it cannot half-configure a backend. -timeout 180s
# because the ProtectToolkit-C emulator can block forever inside
# C_OpenSession; the slowest package here takes seconds, so a hang costs
# three minutes and a goroutine dump rather than the ten-minute default.
run_args=(--rm -v "$REPO_ROOT":/repo -w /repo)
if [ "$WITH_PROTECTSERVER" -eq 1 ]; then
    run_args+=(-v "$PROTECTSERVER_SDK_DIR":"$PROTECTSERVER_SDK_DIR":ro
               -v "$HOME/.cryptoki":/root/.cryptoki
               -e PROTECTSERVER_MODULE -e PROTECTSERVER_WORKSPACE -e PROTECTSERVER_PIN
               -e PROTECTSERVER_ROOT_WORKSPACE -e PROTECTSERVER_INTERMEDIATE_WORKSPACE
               -e PROTECTSERVER_ROOT_PIN -e PROTECTSERVER_INTERMEDIATE_PIN)
fi
suite_status=0
docker run "${run_args[@]}" "$DEV_IMAGE" sh -c '
    git config --global --add safe.directory /repo
    go test -race -p 1 -timeout 180s -v -buildvcs=false ./...
' > "$LOG_DIR/suite.log" 2>&1 || suite_status=$?

# The anchored pattern from docs/test-matrix.md section 3: a top-level
# per-backend subtest, never a nested one and never a PASS line with its
# timing suffix.
count_backend() {
    local backend="$1" kind="$2"
    grep -cE "^    --- $kind: Test[A-Za-z0-9_]+/$backend " "$LOG_DIR/suite.log" || true
}
for backend in SoftHSM2 ProtectServer; do
    printf '    %-14s passed %3s  skipped %3s  failed %3s\n' "$backend" \
        "$(count_backend "$backend" PASS)" "$(count_backend "$backend" SKIP)" "$(count_backend "$backend" FAIL)"
done
grep -E '^(ok|FAIL|---)' "$LOG_DIR/suite.log" | grep -cE '^ok' | sed 's/^/    packages ok: /'
if [ "$suite_status" -ne 0 ]; then
    grep -E '^(--- FAIL|FAIL)' "$LOG_DIR/suite.log" | head -20
    # A killed test binary runs no t.Cleanup, so a timed-out run leaves its
    # objects on a persistent vendor token, and on the emulator the next
    # run's provisioning tests then fail their duplicate-key check.
    if [ "$WITH_PROTECTSERVER" -eq 1 ] && grep -q '^panic: test timed out' "$LOG_DIR/suite.log"; then
        # The goroutine dump is the evidence for the hang, and the next run
        # overwrites suite.log; keep this one under its own name.
        kept="$LOG_DIR/suite-timeout-$(date -u +%Y%m%dT%H%M%SZ).log"
        cp "$LOG_DIR/suite.log" "$kept"
        echo "    the timed-out run's log, goroutine dump included, is kept at $kept"
        echo "    a package timed out: before the next run, clear its leftovers with"
        echo "    go run ./ci/token-cleanup -adapter protectserver -module \"$PROTECTSERVER_MODULE\" -workspace \"$PROTECTSERVER_WORKSPACE\" -pin-env PROTECTSERVER_PIN -prefix conf-"
        echo "    inside $DEV_IMAGE with the suite's mounts and variables; dry run first, then"
        echo "    the same command with -confirm (docs/test-matrix.md section 6)"
    fi
    fail "the suite failed (full log: $LOG_DIR/suite.log)"
fi
if [ "$WITH_PROTECTSERVER" -eq 1 ] && [ "$(count_backend ProtectServer PASS)" -eq 0 ]; then
    fail "--with-protectserver was given but no ProtectServer subtest ran; check the variables against docs/test-matrix.md"
fi

# ---------------------------------------------------------------------------
if [ "$SMOKE" -eq 1 ]; then
    log "4/4  the local deployment, up once and queried"
    # run-local builds the service image, runs the ceremony on two SoftHSM2
    # tokens, mints the credentials and execs the service in the foreground.
    # It is started in the background here, queried on its public port, and
    # stopped by removing its container, which ends the exec. --reset only
    # on a workstation with no local state yet: an existing state belongs to
    # the operator and is reused, as run-local itself does.
    smoke_args=()
    [ -d "$REPO_ROOT/.local/dev" ] || smoke_args=(--reset)
    docker rm -f hsm-pki-local >/dev/null 2>&1 || true
    deploy/docker/run-local.sh "${smoke_args[@]}" > "$LOG_DIR/run-local.log" 2>&1 < /dev/null &
    runlocal_pid=$!
    deadline=$((SECONDS + 900))
    ready=0
    while [ "$SECONDS" -lt "$deadline" ]; do
        if curl -sf "http://localhost:$PORT/readyz" >/dev/null 2>&1; then ready=1; break; fi
        if ! kill -0 "$runlocal_pid" 2>/dev/null; then break; fi
        sleep 3
    done
    if [ "$ready" -ne 1 ]; then
        tail -30 "$LOG_DIR/run-local.log"
        docker rm -f hsm-pki-local >/dev/null 2>&1 || true
        fail "the service did not answer /readyz on port $PORT (full log: $LOG_DIR/run-local.log)"
    fi
    echo "    /readyz: $(curl -s "http://localhost:$PORT/readyz")"
    # Parsed by openssl, not by this repository's code: the CRL is an interop
    # contract, and reading it back through the library that wrote it would
    # prove nothing.
    crl_summary="$(curl -s "http://localhost:$PORT/crl" | openssl crl -inform DER -noout -lastupdate -nextupdate 2>&1 | tr '\n' ' ')"
    echo "    /crl parsed by openssl: $crl_summary"
    echo "    /root.crt: $(curl -sI "http://localhost:$PORT/root.crt" | grep -i '^content-type' | tr -d '\r')"
    docker rm -f hsm-pki-local >/dev/null 2>&1 || true
    wait "$runlocal_pid" 2>/dev/null || true
    echo "    service stopped; local state kept in .local/dev for deploy/k8s/overlays/dev/k3d-up.sh"
else
    log "4/4  smoke skipped (--no-smoke)"
fi

# ---------------------------------------------------------------------------
log "done"
cat <<EOF
  Logs: $LOG_DIR/{build,suite,run-local}.log

  Next, as needed:
    gh auth login                                  # pull requests and checks from the terminal
    deploy/docker/run-local.sh                     # the service, in the foreground
    deploy/k8s/overlays/dev/k3d-up.sh              # the same on a local Kubernetes cluster
    docs/test-matrix.md, sections 5 and 6          # what a vendor backend must provide, and how to run against it
EOF
