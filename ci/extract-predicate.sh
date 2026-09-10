#!/usr/bin/env bash
#
# Extract the predicate from a verified attestation envelope, after
# checking that the statement is about the expected digest.
#
#   ci/extract-predicate.sh <envelope.json> <sha256:digest> <predicate-out.json>
#
# ci/countersign-release.sh uses this to re-attest, with the durable key,
# the SBOM and the provenance the pipeline attested keyless. The predicate
# is taken from the verified statement, so what the durable key signs is
# what the pipeline signed.
set -euo pipefail

ENVELOPE="${1:?usage: ci/extract-predicate.sh <envelope.json> <sha256:digest> <predicate-out.json>}"
WANT_DIGEST="${2:?missing digest}"
OUT="${3:?missing output path}"

python3 - "$ENVELOPE" "$WANT_DIGEST" "$OUT" <<'PY'
import base64, json, sys

envelope_path, want_digest, out = sys.argv[1], sys.argv[2], sys.argv[3]
line = next((l for l in open(envelope_path) if l.strip()), None)
if line is None:
    sys.exit("extract-predicate: the envelope file is empty")
doc = json.loads(line)
envelope = doc.get("dsseEnvelope", doc)
statement = json.loads(base64.b64decode(envelope["payload"]))

got = {"sha256:" + s.get("digest", {}).get("sha256", "") for s in statement.get("subject") or []}
if want_digest not in got:
    sys.exit(f"extract-predicate: the statement is about {sorted(got)}, not {want_digest}")

with open(out, "w") as fh:
    json.dump(statement["predicate"], fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"    {statement.get('predicateType')} -> {out}")
PY
