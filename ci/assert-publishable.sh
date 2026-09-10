#!/usr/bin/env bash
#
# Refuse to publish unless every gate passed in this run.
#
#   ci/assert-publishable.sh
#
# Reads its inputs from the environment, so the workflow can pass
# ${{ needs.<job>.result }} directly:
#
#   PUBLISH_EVENT     github.event_name
#   PUBLISH_REF       github.ref
#   PUBLISH_GATES     "suite=success sast=success ..." for every gate job
#
# The if: on the publish job is the real control. This is the check that
# survives somebody editing it, and it catches three things the if: does
# not: a gate that did not run (needs and if interact in ways that are
# easy to read wrongly), a gate that was deleted (REQUIRED_GATES is written
# out here, so removing a job fails this check), and a gate that was added
# but never required (an unknown name is refused).
#
# Anything unrecognised, missing, empty or not "success" is a refusal.
set -euo pipefail

# The gates that must have passed. ci.yml passes exactly these.
REQUIRED_GATES="suite sast gitleaks deps image terraform trustchain"

die() { echo "assert-publishable: $*" >&2; exit 1; }

EVENT="${PUBLISH_EVENT:-}"
REF="${PUBLISH_REF:-}"
GATES="${PUBLISH_GATES:-}"

# A pull request never publishes, from a fork or otherwise.
[ "$EVENT" = "push" ] || die \
    "refusing to publish: event is '${EVENT:-<unset>}', not 'push'.
Only a push to the default branch publishes; a pull request -- from a fork
or otherwise -- must never reach this step."

# A push to main publishes, and so does a push of a release tag v<x.y.z>.
# Nothing else does: a pre-release tag, a branch, or a tag of another
# shape is refused.
case "$REF" in
    refs/heads/main) ;;
    *)
        [[ "$REF" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die \
            "refusing to publish: ref is '${REF:-<unset>}', not 'refs/heads/main' or a release tag 'refs/tags/v<x.y.z>'." ;;
esac

[ -n "$GATES" ] || die \
    "refusing to publish: no gate results were supplied."

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
Either ci.yml stopped passing it in, or the job was removed." ;;
    esac
done

echo "assert-publishable: push to refs/heads/main, all $(echo $REQUIRED_GATES | wc -w) gates green"
for req in $REQUIRED_GATES; do echo "    $req: success"; done
