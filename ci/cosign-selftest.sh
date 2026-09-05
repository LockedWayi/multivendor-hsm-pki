#!/usr/bin/env bash
#
# Lateral tests for ci/cosign.sh's guards.
#
# Every check in that script exists because something failed open. A guard
# nobody can trigger deliberately is a guard nobody has seen work, so each
# one is exercised here against the boundary case it is meant to catch --
# the same discipline as 4.6's "prove the gate fails" and 4.8's lateral
# tests around the duplicate-key check.
#
# Run:  ci/cosign-selftest.sh
#
# No downloads and no HSM: the cases that need a cosign use a stand-in that
# prints one measured output shape. The strings are not invented -- each was
# captured from a real binary before being reproduced here:
#
#   "This cosign was not built with pkcs11-tool support!"  cosign-linux-amd64 v3.1.3
#   "failed to load PKCS11 module"                         the pkcs11key build, no module
#   "Listing tokens of PKCS11 module '...'"                the pkcs11key build, module present
#
# The stand-ins cover what the real binaries cannot produce on demand --
# garbage, silence, a message that changes in some future release -- while
# the end-to-end evidence stays what it was: the real pkcs11key build is
# accepted and the real default build is refused, both recorded in
# 4.9.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap "rm -rf '$WORK'" EXIT

# shellcheck source=ci/cosign.sh
source "$REPO_ROOT/ci/cosign.sh"
# The sourced script sets -e for its own benefit, and it lands in this shell
# too. Every case here deliberately runs a guard that is expected to fail, so
# -e would end the suite at the first success.
set +e

pass=0; fail=0

# expect <"accept"|"refuse"> <name> -- runs the rest as a command in a
# subshell, since the guards report failure by exiting.
expect() {
    local want="$1" name="$2"; shift 2
    local out status
    out="$("$@" 2>&1)"; status=$?
    local got="accept"; [ "$status" -ne 0 ] && got="refuse"
    if [ "$got" = "$want" ]; then
        printf '  ok    %-58s (%s)\n' "$name" "$got"
        pass=$((pass+1))
    else
        printf '  FAIL  %-58s (wanted %s, got %s)\n' "$name" "$want" "$got"
        printf '        %s\n' "${out//$'\n'/$'\n'        }"
        fail=$((fail+1))
    fi
}

stand_in() {   # stand_in <name> <exit code> <stdout text>
    local path="$WORK/$1"
    { echo '#!/bin/sh'; printf 'echo %q\n' "$3"; echo "exit $2"; } > "$path"
    chmod +x "$path"
    echo "$path"
}

echo
echo "A. assert_pkcs11_build classifies what the binary says"
ensure_runner_image
expect refuse "A1 the stub build's refusal, exit 0" \
    assert_pkcs11_build "$(stand_in a1 0 'This cosign was not built with pkcs11-tool support!')"
expect accept "A2 no module to load, exit 1" \
    assert_pkcs11_build "$(stand_in a2 1 'Error: failed to load PKCS11 module')"
expect accept "A3 a module was loaded and tokens listed, exit 0" \
    assert_pkcs11_build "$(stand_in a3 0 "Listing tokens of PKCS11 module '/pkcs11/libsofthsm2.so'")"
expect refuse "A4 output nobody recognises" \
    assert_pkcs11_build "$(stand_in a4 0 'Segmentation fault (core dumped)')"
expect refuse "A5 silence, exit 0" \
    assert_pkcs11_build "$(stand_in a5 0 '')"
# Ordering matters: a stub that also mentions loading a module must still be
# refused, so the refusal branch has to be matched first.
expect refuse "A6 refusal *and* an accept phrase in one output" \
    assert_pkcs11_build "$(stand_in a6 0 'failed to load PKCS11 module: This cosign was not built with pkcs11-tool support!')"

echo
echo "B. run refuses missing signing state instead of letting docker invent it"
COSIGN_BIN="$(stand_in fake-cosign 0 'unused')"
# The pin check runs before the state check, so this suite pins the stand-in.
COSIGN_SHA256="$(sha256sum "$COSIGN_BIN" | cut -d' ' -f1)"

STATE="$WORK/absent"
expect refuse "B1 no signing state at all" run pkcs11-tool list-tokens
[ -e "$STATE" ] && { echo "  FAIL  B1 created $STATE on the host"; fail=$((fail+1)); } \
                || { echo "  ok    B1 created nothing"; pass=$((pass+1)); }

STATE="$WORK/partial"; mkdir -p "$STATE/pkcs11"
expect refuse "B2 partial state (pkcs11 present, tokens and etc missing)" run pkcs11-tool list-tokens
if [ -e "$STATE/tokens" ] || [ -e "$STATE/etc" ]; then
    echo "  FAIL  B2 filled in the missing directories"; fail=$((fail+1))
else
    echo "  ok    B2 left the gap rather than filling it"; pass=$((pass+1))
fi

echo
echo "C. the pinned digest is re-checked at every run, not only at fetch"
STATE="$WORK/complete"; mkdir -p "$STATE"/{pkcs11,tokens,etc}
printf 'tampered\n' >> "$COSIGN_BIN"
expect refuse "C1 an installed binary whose bytes changed" run pkcs11-tool list-tokens

echo
echo "D. a failed fetch leaves an already-good binary alone"
GOOD="$WORK/installed/cosign"; mkdir -p "$WORK/installed"
printf 'the binary that was already there\n' > "$GOOD"; chmod +x "$GOOD"
before="$(sha256sum "$GOOD" | cut -d' ' -f1)"
BIN_DIR="$WORK/installed"; COSIGN_BIN="$GOOD"
COSIGN_SHA256="0000000000000000000000000000000000000000000000000000000000000000"
# Compared as a set difference rather than a count. This suite runs from its
# own mktemp directory, so "are there any temp dirs left" can never be no --
# the first version of this check said so and could not fail.
#
# And the directory is asked of mktemp rather than assumed to be /tmp.
# mktemp honours $TMPDIR, so a hardcoded /tmp/tmp.* glob finds nothing
# wherever TMPDIR points elsewhere -- macOS puts it under /var/folders by
# default, and any Linux shell can set it -- and the check would then pass
# vacuously while a real leak went unseen. Measured: with TMPDIR elsewhere,
# the glob matched 0 of 1 leaked directories.
tmp_root="$(dirname "$(mktemp -d -u)")"
leak_glob() { ls -d "$tmp_root"/tmp.* 2>/dev/null | sort; }
tmp_before="$(leak_glob)"
expect refuse "D1 fetch with a pin nothing can satisfy" fetch
tmp_after="$(leak_glob)"
after="$(sha256sum "$GOOD" | cut -d' ' -f1)"
if [ "$before" = "$after" ]; then
    echo "  ok    D1 the existing binary is untouched"; pass=$((pass+1))
else
    echo "  FAIL  D1 the existing binary was modified"; fail=$((fail+1))
fi
leaked="$(comm -13 <(echo "$tmp_before") <(echo "$tmp_after"))"
if [ -z "$leaked" ]; then
    echo "  ok    D1 the rejected download left no temp directory"; pass=$((pass+1))
else
    echo "  FAIL  D1 leaked: $leaked"; fail=$((fail+1))
fi

echo
echo "E. the Rekor check refuses a response that records nothing"
rekor_fixture() { printf '%s' "$2" > "$WORK/$1.json"; echo "$WORK/$1.json"; }
DIGEST="549398fbe5a2f930b4eb564c7bbe9588270566ffcc8c9cb45644c066714aa380"
# The case that shipped: valid JSON, no entry. A loop over it checks nothing
# and returns success, which reads as "publicly logged" to the caller.
expect refuse "E1 an empty object" \
    assert_rekor_records "$(rekor_fixture e1 '{}')" "$DIGEST"
expect refuse "E2 an entry recording a different digest" \
    assert_rekor_records "$(rekor_fixture e2 "{\"abc\":{\"body\":\"$(printf '{"spec":{"data":{"hash":{"value":"deadbeef"}},"signature":{"publicKey":{"content":"eA=="}}}}' | base64 -w0)\"}}")" "$DIGEST"

echo
echo "F. sign-artifact refuses a path the container cannot reach"
# Measured before this guard existed: signing /etc/hostname made cosign hash
# the *container's* /etc/hostname and sign it, successfully, under the right
# key -- the wrong file, correctly signed. The check runs before signing, so
# a throwaway PIN is enough to reach it and the token is never opened.
expect refuse "F1 an artifact outside the repository" \
    env COSIGN_PKCS11_PIN=unused "$REPO_ROOT/ci/sign-artifact.sh" /etc/hostname
expect refuse "F2 a bundle written outside the repository" \
    env COSIGN_PKCS11_PIN=unused "$REPO_ROOT/ci/sign-artifact.sh" \
        "$REPO_ROOT/internal/artifactsig/testdata/sample-artifact.txt" /tmp/escapes.bundle
[ -e /tmp/escapes.bundle ] && { echo "  FAIL  F2 wrote a bundle anyway"; fail=$((fail+1)); } \
                           || { echo "  ok    F2 wrote nothing"; pass=$((pass+1)); }

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
