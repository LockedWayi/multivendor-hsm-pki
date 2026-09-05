#!/usr/bin/env bash
#
# Exercise ci/assert-publishable.sh, in both directions.
#
# A guard nobody has watched fail proves nothing: it is indistinguishable,
# from the outside, from a script that exits 0 unconditionally. So every
# refusal below is asserted to happen, and the accept case is asserted not
# to. This runs in CI as part of a required check, so a guard that stops
# guarding blocks the merge that broke it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HERE/assert-publishable.sh"

ALL_GREEN="suite=success sast=success gitleaks=success deps=success image=success terraform=success"

failures=0
pass() { printf '  ok      %s\n' "$1"; }
fail() { printf '  FAILED  %s\n' "$1" >&2; failures=$((failures + 1)); }

# accepts <name> -- the guard must exit 0
accepts() {
    local name="$1"; shift
    if env "$@" "$GUARD" >/dev/null 2>&1; then pass "$name"; else fail "$name (expected accept, got refusal)"; fi
}

# refuses <name> <expected-substring> -- the guard must exit non-zero AND
# say why. The message is asserted too: a refusal for the wrong reason is
# how a test passes while the thing it tests is broken.
refuses() {
    local name="$1" want="$2"; shift 2
    local out status
    out="$(env "$@" "$GUARD" 2>&1)" && status=0 || status=$?
    if [ "$status" -eq 0 ]; then
        fail "$name (expected refusal, got accept)"
    elif ! printf '%s' "$out" | grep -qF "$want"; then
        fail "$name (refused, but not for the stated reason; wanted '$want')"
        printf '          got: %s\n' "$(printf '%s' "$out" | head -2)" >&2
    else
        pass "$name"
    fi
}

echo "== the one accept =="
accepts "push to main with every gate green" \
    PUBLISH_EVENT=push PUBLISH_REF=refs/heads/main PUBLISH_GATES="$ALL_GREEN"

echo "== wrong event or ref =="
refuses "a pull request never publishes" "not 'push'" \
    PUBLISH_EVENT=pull_request PUBLISH_REF=refs/heads/main PUBLISH_GATES="$ALL_GREEN"
refuses "a fork's pull_request_target never publishes" "not 'push'" \
    PUBLISH_EVENT=pull_request_target PUBLISH_REF=refs/heads/main PUBLISH_GATES="$ALL_GREEN"
refuses "an unset event never publishes" "<unset>" \
    PUBLISH_EVENT= PUBLISH_REF=refs/heads/main PUBLISH_GATES="$ALL_GREEN"
refuses "a push to another branch never publishes" "not 'refs/heads/main'" \
    PUBLISH_EVENT=push PUBLISH_REF=refs/heads/feature PUBLISH_GATES="$ALL_GREEN"
refuses "a tag push never publishes" "not 'refs/heads/main'" \
    PUBLISH_EVENT=push PUBLISH_REF=refs/tags/v9.9.9 PUBLISH_GATES="$ALL_GREEN"

echo "== a gate that did not pass =="
for gate in suite sast gitleaks deps image terraform; do
    for result in failure cancelled skipped ""; do
        refuses "$gate=${result:-<empty>} blocks the publish" "gate '$gate' is" \
            PUBLISH_EVENT=push PUBLISH_REF=refs/heads/main \
            PUBLISH_GATES="$(printf '%s' "$ALL_GREEN" | sed "s/${gate}=success/${gate}=${result}/")"
    done
done

echo "== a gate that went missing =="
for gate in suite sast gitleaks deps image terraform; do
    refuses "removing $gate blocks the publish" "gate '$gate' reported no result" \
        PUBLISH_EVENT=push PUBLISH_REF=refs/heads/main \
        PUBLISH_GATES="$(printf '%s' "$ALL_GREEN" | sed "s/${gate}=success//")"
done
refuses "no results at all blocks the publish" "absence of evidence" \
    PUBLISH_EVENT=push PUBLISH_REF=refs/heads/main PUBLISH_GATES=

echo "== drift between ci.yml and the required list =="
refuses "a gate passed in but never required blocks the publish" "unrecognised gate 'newscanner'" \
    PUBLISH_EVENT=push PUBLISH_REF=refs/heads/main PUBLISH_GATES="$ALL_GREEN newscanner=success"
refuses "a malformed result blocks the publish" "malformed gate result" \
    PUBLISH_EVENT=push PUBLISH_REF=refs/heads/main PUBLISH_GATES="$ALL_GREEN suite"
refuses "a duplicated gate blocks the publish" "supplied twice" \
    PUBLISH_EVENT=push PUBLISH_REF=refs/heads/main PUBLISH_GATES="$ALL_GREEN suite=success"

echo
if [ "$failures" -ne 0 ]; then
    echo "assert-publishable-selftest: $failures case(s) failed" >&2
    exit 1
fi
echo "assert-publishable-selftest: all cases behaved as specified"
