#!/usr/bin/env bash
#
# Decide whether a change needs ci/signing-mechanism-test.sh run against it.
#
#   ci/mechanism-test-needed.sh <base-ref>   # exit 0 = needed, 1 = not
#
# Why this exists. The mechanism test is the only thing in the pipeline
# that reads a signed predicate back out of a registry, and it runs from
# ci/publish-image.sh -- on merge. The publish and signature-verification
# jobs are skipped on pull requests. So a change to what the SBOM
# *contains or is encoded as* is first exercised after it lands.
#
# That is not hypothetical. Bumping trivy from 0.67.0 to 0.74.0 moved the
# CycloneDX output from specVersion 1.6 to 1.7 -- same components, a
# different schema on an artifact cosign signs and reads back. It was run
# by hand that time.
#
# The paths below are the inputs that can change the signed artifacts or
# the tools that produce them. Two things follow from that sentence:
#
#   - this list is a security control, not a convenience. An input that
#     belongs here and is missing restores the gap silently, which is the
#     failure this whole file exists to prevent;
#   - it lives beside the pins it guards, so adding a scanner pin and
#     forgetting the filter is one file away rather than two.
#
# Add a path when it changes the image, the SBOM, the provenance, or any
# tool that signs or verifies them.
set -euo pipefail

BASE="${1:-}"
[ -n "$BASE" ] || { echo "usage: ci/mechanism-test-needed.sh <base-ref>" >&2; exit 2; }

WATCHED=(
    'ci/scanner-pins.sh'            # the scanner and tool digests
    'ci/scan-image.sh'              # produces the SBOM that gets attested
    'ci/cosign.sh'                  # every signature goes through it
    'ci/sign-image.sh'              # makes the image signature
    'ci/sign-artifact.sh'           # makes the release binary signature
    'ci/active-signing-key.sh'      # decides which key version signs
    'ci/select-key/main.go'         # the selection the line above calls
    'ci/cosign.Dockerfile'          # the cosign runtime
    'ci/attest-image.sh'            # writes the attestations
    'ci/generate-provenance.sh'     # the provenance predicate
    'ci/extract-predicate.sh'       # reads a predicate back
    'ci/publish-image.sh'           # the order the whole thing happens in
    'ci/signing-mechanism-test.sh'  # the test itself
    'ci/rotation-drill.sh'          # the rotation drill, run in the same job
    'cmd/hsm-pki-keytool/retire.go'     # retires a key: reads the inventory, then destroys
    'cmd/hsm-pki-keytool/provision.go'  # provisions the next key version
    'cmd/hsm-pki-keytool/inventory.go'  # publishes what the signers and verifiers read
    'ci/mechanism-test-needed.sh'   # this list; a change to it is exercised
    'ci/verify-run-artifacts.sh'    # the public-key-only verifier
    'ci/verify-release.sh'
    'ci/verify-keyless.sh'
    'ci/keyless-identity.sh'
    'deploy/docker/Dockerfile'      # the image being signed
    'deploy/docker/provision-signing-keys.sh'
)

changed="$(git diff --name-only "$BASE"...HEAD)"
if [ -z "$changed" ]; then
    echo "mechanism-test-needed: no files changed against $BASE"
    exit 1
fi

matched=()
for path in "${WATCHED[@]}"; do
    if printf '%s\n' "$changed" | grep -qxF "$path"; then
        matched+=("$path")
    fi
done

if [ "${#matched[@]}" -eq 0 ]; then
    echo "mechanism-test-needed: no watched path changed against $BASE"
    echo "    watched: ${#WATCHED[@]} paths, see this script"
    echo "    changed: $(printf '%s\n' "$changed" | wc -l) files, none of them watched"
    exit 1
fi

echo "mechanism-test-needed: ${#matched[@]} watched path(s) changed against $BASE"
printf '    %s\n' "${matched[@]}"
exit 0
