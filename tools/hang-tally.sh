#!/usr/bin/env bash
#
# Count how often the ProtectToolkit-C emulator hangs the suite.
#
#   tools/hang-tally.sh <runs> <tag> <out-dir>
#
# Runs the whole suite <runs> times in the dev image against SoftHSM2 and
# the emulator (the seven PROTECTSERVER_* variables, docs/test-matrix.md
# section 6), uncached (-count=1), one line of summary per run. A run the
# -timeout kills is a hang: its log is kept under <out-dir>/<tag>-<n>.log
# with the goroutine dump, the ProtectServer conformance case it parked at
# is printed, and ci/token-cleanup -prefix conf- runs before the next run
# (dry, then -confirm), because a killed test binary runs no t.Cleanup and
# the emulator's deterministic RNG turns leftovers into duplicate-key
# failures in later packages. Never stop a hung run by hand; the dump is
# the evidence.
#
# HANG_ENV, when set, is passed to docker run as extra flags, for example
# HANG_ENV="-e HSM_PKI_MODULE_THREAD=1" to measure a branch's experiment
# switch. Written for the open 6.1 item; the tally so far is in
# docs/test-matrix.md section 6.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1
N="${1:?runs}"; TAG="${2:?tag}"; OUT="${3:?out dir}"
mkdir -p "$OUT"
for v in PROTECTSERVER_MODULE PROTECTSERVER_WORKSPACE PROTECTSERVER_PIN \
         PROTECTSERVER_ROOT_WORKSPACE PROTECTSERVER_INTERMEDIATE_WORKSPACE \
         PROTECTSERVER_ROOT_PIN PROTECTSERVER_INTERMEDIATE_PIN; do
    [ -n "${!v:-}" ] || { echo "hang-tally: $v is not set" >&2; exit 2; }
done
DEV_IMAGE="${DEV_IMAGE:-hsm-pki-dev}"
PROTECTSERVER_SDK_DIR="${PROTECTSERVER_SDK_DIR:-/opt/safenet}"

# shellcheck disable=SC2086  # HANG_ENV is a list of flags by design
run() {
    docker run --rm -v "$REPO_ROOT":/repo -w /repo \
        -v "$PROTECTSERVER_SDK_DIR":"$PROTECTSERVER_SDK_DIR":ro -v "$HOME/.cryptoki":/root/.cryptoki \
        -e PROTECTSERVER_MODULE -e PROTECTSERVER_WORKSPACE -e PROTECTSERVER_PIN \
        -e PROTECTSERVER_ROOT_WORKSPACE -e PROTECTSERVER_INTERMEDIATE_WORKSPACE \
        -e PROTECTSERVER_ROOT_PIN -e PROTECTSERVER_INTERMEDIATE_PIN \
        ${HANG_ENV:-} "$DEV_IMAGE" "$@"
}
cleanup() {
    run go run -buildvcs=false ./ci/token-cleanup -adapter protectserver -module "$PROTECTSERVER_MODULE" \
        -workspace "$PROTECTSERVER_WORKSPACE" -pin-env PROTECTSERVER_PIN -prefix conf- "$@" 2>&1 | grep -E 'objects total|destroyed' | sed 's/^/    /'
}

hangs=0
for i in $(seq 1 "$N"); do
    L="$OUT/$TAG-$i.log"; start=$SECONDS
    run go test -race -p 1 -count=1 -timeout 180s -buildvcs=false -v ./... > "$L" 2>&1; rc=$?
    hung=$(grep -c '^panic: test timed out' "$L")
    where=$(grep -oE '^\s*=== RUN\s+TestConformance/ProtectServer/[A-Za-z0-9_]+' "$L" | tail -1 | awk '{print $3}')
    position=$(grep -cE '^\s*=== RUN\s+TestConformance/ProtectServer/[A-Za-z0-9_]+' "$L")
    echo "$TAG run $i: rc=$rc hung=$hung seconds=$((SECONDS - start)) packages_ok=$(grep -c '^ok' "$L") cached=$(grep -c '(cached)' "$L") last_case=$position:${where:-none}"
    if [ "$hung" -gt 0 ]; then
        hangs=$((hangs + 1))
        grep -oE 'pkcs11\.\(\*Ctx\)\.[A-Za-z]+' "$L" | sort | uniq -c | sort -rn | head -2 | sed 's/^/    in module: /'
        cleanup
        cleanup -confirm
    fi
done
echo "$TAG: $hangs hangs in $N runs"
