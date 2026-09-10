#!/usr/bin/env bash
#
# Emit a SLSA v1.0 provenance predicate for the image this run built.
#
#   ci/generate-provenance.sh <output.json>
#
# Provenance is a claim about a build environment: who built it, from
# which source, on whose infrastructure. Every field is only worth
# recording because something else can corroborate it. A predicate
# generated on a laptop with plausible values signs as well as a true one,
# so the GITHUB_* variables are required. ci/signing-mechanism-test.sh
# sets placeholders naming mechanism-test.invalid for its throwaway
# registry.
#
# The predicate is attested keyless by the pipeline, and re-attested with
# image-signing-key-v1 on release digests by ci/countersign-release.sh.
set -euo pipefail

die() { echo "generate-provenance: $*" >&2; exit 1; }

OUT="${1:?usage: ci/generate-provenance.sh <output.json>}"

# Named individually so the error says which is missing.
for v in GITHUB_REPOSITORY GITHUB_SHA GITHUB_RUN_ID GITHUB_WORKFLOW_REF \
         GITHUB_SERVER_URL GITHUB_REF GITHUB_RUN_ATTEMPT; do
    [ -n "${!v:-}" ] || die \
        "$v is not set.

Provenance is a claim about the environment that produced an artifact. This
script will not invent one: a predicate filled with plausible values signs
just as well as a true one and a reader cannot tell them apart. Run it from
the pipeline, or do not attest."
done

python3 - "$OUT" <<'PY'
import json, os, sys, datetime

out = sys.argv[1]
repo = os.environ["GITHUB_REPOSITORY"]
server = os.environ["GITHUB_SERVER_URL"].rstrip("/")

# SLSA v1.0. buildDefinition says what was asked for; runDetails says who
# ran it. cosign binds the predicate to the image digest as the subject.
predicate = {
    "buildDefinition": {
        # A URI naming this build process.
        "buildType": f"{server}/{repo}/.github/workflows/ci.yml@publish",
        "externalParameters": {
            "workflow": {
                "ref": os.environ["GITHUB_REF"],
                "repository": f"{server}/{repo}",
                "path": ".github/workflows/ci.yml",
            }
        },
        "internalParameters": {
            "github": {
                "event_name": os.environ.get("GITHUB_EVENT_NAME", ""),
                "runner_environment": os.environ.get("RUNNER_ENVIRONMENT", ""),
            }
        },
        # The source, pinned by commit.
        "resolvedDependencies": [
            {
                "uri": f"git+{server}/{repo}@{os.environ['GITHUB_REF']}",
                "digest": {"gitCommit": os.environ["GITHUB_SHA"]},
            }
        ],
    },
    "runDetails": {
        "builder": {
            # GITHUB_WORKFLOW_REF is the workflow file at a ref, the same
            # string the keyless certificate carries.
            "id": f"{server}/{os.environ['GITHUB_WORKFLOW_REF']}",
        },
        "metadata": {
            "invocationId": (
                f"{server}/{repo}/actions/runs/"
                f"{os.environ['GITHUB_RUN_ID']}/attempts/"
                f"{os.environ['GITHUB_RUN_ATTEMPT']}"
            ),
            "startedOn": datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        },
    },
}

with open(out, "w") as fh:
    json.dump(predicate, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"    builder   {predicate['runDetails']['builder']['id']}")
print(f"    source    {predicate['buildDefinition']['resolvedDependencies'][0]['digest']['gitCommit']}")
print(f"    run       {predicate['runDetails']['metadata']['invocationId']}")
PY
