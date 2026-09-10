#!/usr/bin/env bash
#
# Check what a verified SLSA provenance attestation says.
#
#   ci/check-provenance.sh <envelope.json> <sha256:digest> <commit>
#
# cosign verify-attestation prints the DSSE envelope it verified. This
# reads the first envelope, decodes the in-toto statement and checks that
# the predicate type is SLSA v1, the subject includes the image digest, the
# resolved dependencies name the commit, and the builder id is a URI.
#
# A signed statement about a different artifact verifies as well as a true
# one. cosign's exit status says the key vouches for the statement. This
# script says the statement is about this image and this commit.
set -euo pipefail

ENVELOPE="${1:?usage: ci/check-provenance.sh <envelope.json> <sha256:digest> <commit>}"
WANT_DIGEST="${2:?missing digest}"
WANT_COMMIT="${3:?missing commit}"

python3 - "$ENVELOPE" "$WANT_DIGEST" "$WANT_COMMIT" <<'PY'
import base64, json, sys

envelope_path, want_digest, want_commit = sys.argv[1], sys.argv[2], sys.argv[3]

line = next((l for l in open(envelope_path) if l.strip()), None)
if line is None:
    sys.exit("check-provenance: the envelope file is empty")
doc = json.loads(line)
# cosign v2 prints the DSSE envelope. cosign v3 may print a Sigstore bundle
# that carries the envelope under dsseEnvelope.
envelope = doc.get("dsseEnvelope", doc)
statement = json.loads(base64.b64decode(envelope["payload"]))

problems = []
if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
    problems.append(f"predicateType is {statement.get('predicateType')!r}")

subjects = statement.get("subject") or []
got = {"sha256:" + s.get("digest", {}).get("sha256", "") for s in subjects}
if want_digest not in got:
    problems.append(f"subject digest {sorted(got)} does not include the image {want_digest}")

deps = statement["predicate"]["buildDefinition"].get("resolvedDependencies") or []
commits = {d.get("digest", {}).get("gitCommit") for d in deps}
if want_commit not in commits:
    problems.append(f"resolvedDependencies commit {sorted(c for c in commits if c)} is not {want_commit}")

builder = statement["predicate"]["runDetails"]["builder"].get("id", "")
if not builder.startswith("https://"):
    problems.append(f"builder id {builder!r} is not a URI")

if problems:
    print("check-provenance: the attestation is signed but says the wrong thing:", file=sys.stderr)
    for p in problems:
        print("  -", p, file=sys.stderr)
    sys.exit(1)

print(f"    subject   {want_digest}")
print(f"    source    {want_commit}")
print(f"    builder   {builder}")
PY
