#!/usr/bin/env bash
#
# Every third-party container image reference is pinned by digest.
#
#   ci/check-image-pins.sh
#
# The workflow header claims this. It was false in six places on
# 2026-09-08: ci/softhsm2-dev.Dockerfile ran on a tag, and four scripts
# used a bare alpine:3. The dev image runs the test suite and generates the
# supply-chain signing keys, so a moved tag there is a different toolchain
# generating a private key. The claim is now checked.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

failures=0
fail() { printf '  UNPINNED  %s\n' "$*" >&2; failures=$((failures + 1)); }

# Only files this repository tracks. The first version walked the working
# tree and found a dependency's Dockerfile inside the restored Go module
# cache.
tracked() { git ls-files -z -- "$@"; }

echo "==> Dockerfile FROM lines"
# Every build stage must name a digest.
while IFS= read -r hit; do
    file="${hit%%:*}"
    line="${hit#*:}"
    case "$line" in
        *"@sha256:"*) printf '  ok        %s\n' "$file: ${line#*FROM }" ;;
        # `FROM <stage>` referring to an earlier named stage in the same
        # file is not a third-party reference and has no digest to pin.
        *" AS "*|*)
            ref="$(printf '%s' "$line" | sed -E 's/^FROM +([^ ]+).*/\1/')"
            if grep -qE "^FROM .* AS +$ref\$" "$file"; then
                printf '  ok        %s: %s (earlier stage in this file)\n' "$file" "$ref"
            else
                fail "$file: $line"
            fi ;;
    esac
done < <(tracked '*Dockerfile*' | xargs -0 -r grep -n "^FROM " /dev/null 2>/dev/null | cut -d: -f1,3-)

echo
echo "==> upstream images referenced from scripts and workflows"
# A list of the upstream names this repository uses. A name here without
# @sha256: on the same line is a finding. A new upstream image is added
# here too.
UPSTREAM='alpine|golang|debian|registry|ubuntu|aquasec/trivy|semgrep/semgrep|zricethezav/gitleaks|ghcr\.io/opentofu/opentofu|gcr\.io/distroless'
while IFS= read -r hit; do
    case "$hit" in
        *"@sha256:"*) continue ;;
        # A comment is prose about an image, not a use of one.
        *"#"*) continue ;;
    esac
    fail "$hit"
done < <(tracked 'ci/*.sh' 'ci/*.yml' 'deploy/*.sh' 'deploy/*.yml' 'deploy/*.yaml' \
                 '.github/*.yml' '.github/*.yaml' \
         | xargs -0 -r grep -nE "(^|[^A-Za-z0-9_./-])($UPSTREAM):[A-Za-z0-9._-]+" /dev/null 2>/dev/null \
         | grep -vE "^[^:]*:[0-9]+: *#" || true)

echo
if [ "$failures" -ne 0 ]; then
    echo "check-image-pins: $failures unpinned reference(s)." >&2
    echo "A tag is a pointer somebody else can move, so a tag-pinned image is" >&2
    echo "an image whose contents are chosen by its publisher after review." >&2
    echo "Pin by digest; put shared ones in ci/scanner-pins.sh." >&2
    exit 1
fi
echo "check-image-pins: every third-party image reference is pinned by digest"
