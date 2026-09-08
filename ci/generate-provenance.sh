#!/usr/bin/env bash
#
# Emit a SLSA v1.0 provenance predicate for the image this run built
# (Phase 5.9).
#
#   ci/generate-provenance.sh <output.json>
#
# # Why this refuses to run outside a pipeline
#
# Provenance is a claim about a build *environment*: who built it, from
# which source, on whose infrastructure. Every field below is only worth
# recording because something else can corroborate it -- the run URL
# resolves, the commit exists, the workflow ref is in a public tree.
#
# A predicate generated on a laptop and populated with plausible-looking
# values would carry exactly the same signature and mean nothing, and the
# reader has no way to tell the two apart. So the environment is required
# rather than defaulted: no GITHUB_* variables, no attestation. Inventing a
# builder identity is the one failure mode this file exists to avoid.
#
# # What the resulting attestation does and does not prove
#
# It is signed by image-signing-key-v1 over the same PKCS#11 path as the
# image signature -- no new keys, no new infrastructure. In CI that key is
# provisioned for the run and destroyed with it, so the attestation proves
# the *mechanism*: that this pipeline produces a signed, digest-bound
# provenance statement. It does not make the CI run a durable identity, and
# it is not evidence of custody. The honest split of 2.3 applies here
# exactly as it does to the signatures.
set -euo pipefail

die() { echo "generate-provenance: $*" >&2; exit 1; }

OUT="${1:?usage: ci/generate-provenance.sh <output.json>}"

# Required, every one of them, and named individually so the error says
# which is missing rather than "not in CI".
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
# ran it and where the record lives. Nothing here is derived from the
# artifact itself -- cosign binds the predicate to the image digest as the
# statement's subject, which is what makes the pair meaningful.
predicate = {
    "buildDefinition": {
        # A URI naming *this* build process, not a generic one. It is the
        # thing a consumer would look up to learn what these parameters mean.
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
        # The source, pinned by commit. gitCommit rather than sha256: the
        # digest algorithm names what is being identified, and a git commit
        # is not the sha256 of the tree.
        "resolvedDependencies": [
            {
                "uri": f"git+{server}/{repo}@{os.environ['GITHUB_REF']}",
                "digest": {"gitCommit": os.environ["GITHUB_SHA"]},
            }
        ],
    },
    "runDetails": {
        "builder": {
            # GITHUB_WORKFLOW_REF is the workflow file at a ref -- the
            # closest thing Actions has to a builder identity, and the same
            # string a keyless Fulcio certificate would carry.
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
