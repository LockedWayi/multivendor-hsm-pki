#!/usr/bin/env bash
#
# Refuse to publish unless this run is the one the gates actually gated.
#
#   ci/assert-publishable.sh
#
# Reads its inputs from the environment so the workflow can hand it
# ${{ needs.<job>.result }} directly:
#
#   PUBLISH_EVENT     github.event_name
#   PUBLISH_REF       github.ref
#   PUBLISH_GATES     "suite=success sast=success ..." for every gate job
#
# # Why this exists when the job already has an `if:`
#
# The `if:` on the publish job is the real control and this does not replace
# it. This is the check that survives somebody editing it.
#
# Three failures it is built to catch, none of which the `if:` sees:
#
#   1. A gate that did not run. GitHub skips a dependent job when a needed
#      job fails -- but `needs` and `if` interact in ways that are easy to
#      get wrong (a status function such as always() in the condition
#      replaces the implicit success requirement outright), and the way that
#      goes wrong is a publish step that runs anyway. Rather than depend on
#      reading those semantics correctly, the results are passed in and
#      compared here.
#
#   2. A gate that was deleted. REQUIRED_GATES is written out below rather
#      than derived from whatever the workflow happened to pass in, so
#      removing a job from ci.yml fails this check instead of silently
#      shrinking the set of things being enforced. That is the difference
#      between a gate and a list.
#
#   3. A gate that was added but never required. An unrecognised name is
#      refused for the mirror-image reason: a new scanner whose result is
#      passed in but not listed here would be reported and not enforced,
#      which is the exact shape of a check that examines everything and
#      blocks nothing.
#
# Fail closed (CLAUDE.md 3.4): anything unrecognised, missing, empty or
# merely not-'success' is a refusal. There is no path through this script
# that publishes on a maybe.
set -euo pipefail

# The gates that must have passed for an artifact to be publishable. This
# list is the contract; ci.yml must pass exactly these and no others.
REQUIRED_GATES="suite sast gitleaks deps image terraform trustchain"

die() { echo "assert-publishable: $*" >&2; exit 1; }

EVENT="${PUBLISH_EVENT:-}"
REF="${PUBLISH_REF:-}"
GATES="${PUBLISH_GATES:-}"

# A pull request never publishes, and that includes one from a fork. A fork's
# pull_request run gets a read-only token and no secrets, so it could not
# push even if it reached this far -- but "the credential would not have
# worked" is a weaker statement than "the step does not run", and only the
# second one stays true when the credentials change.
[ "$EVENT" = "push" ] || die \
    "refusing to publish: event is '${EVENT:-<unset>}', not 'push'.
Only a push to the default branch publishes; a pull request -- from a fork
or otherwise -- must never reach this step."

[ "$REF" = "refs/heads/main" ] || die \
    "refusing to publish: ref is '${REF:-<unset>}', not 'refs/heads/main'."

[ -n "$GATES" ] || die \
    "refusing to publish: no gate results were supplied. An empty result set
is not an absence of failures, it is an absence of evidence."

# Every supplied result must be a gate this script knows about, and every
# gate this script knows about must have been supplied and have passed.
seen=""
for pair in $GATES; do
    case "$pair" in
        *=*) ;;
        *) die "refusing to publish: malformed gate result '$pair' (want name=result)" ;;
    esac
    name="${pair%%=*}"
    result="${pair#*=}"

    known=0
    for req in $REQUIRED_GATES; do
        [ "$name" = "$req" ] && known=1
    done
    [ "$known" = "1" ] || die \
        "refusing to publish: unrecognised gate '$name'.
It is passed in by ci.yml but not listed in REQUIRED_GATES here, so its
result would be reported and not enforced. Add it to the list."

    case " $seen " in
        *" $name "*) die "refusing to publish: gate '$name' supplied twice" ;;
    esac
    seen="$seen $name"

    [ "$result" = "success" ] || die \
        "refusing to publish: gate '$name' is '$result', not 'success'.
Nothing that has not passed every gate gets published."
done

for req in $REQUIRED_GATES; do
    case " $seen " in
        *" $req "*) ;;
        *) die \
            "refusing to publish: gate '$req' reported no result at all.
Either ci.yml stopped passing it in, or the job was removed. A gate that
does not report is not a gate that passed." ;;
    esac
done

echo "assert-publishable: push to refs/heads/main, all $(echo $REQUIRED_GATES | wc -w) gates green"
for req in $REQUIRED_GATES; do echo "    $req: success"; done
