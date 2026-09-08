#!/usr/bin/env bash
#
# Every third-party container image reference is pinned by digest.
#
#   ci/check-image-pins.sh
#
# ci.yml's header has claimed this since Phase 5.1. On 2026-09-08 it was
# false in six places, and the two that mattered were not the obvious ones:
# ci/softhsm2-dev.Dockerfile ran on a *tag*, and that image runs the whole
# test suite, the coverage floor, the local CA -- and generates the
# supply-chain signing keys. A moved tag there is a different toolchain
# generating a private key.
#
# The other four were bare `alpine:3` in scripts that chown a signature
# bundle and delete token state. ci/scanner-pins.sh had already pinned
# alpine by digest, with a comment saying in as many words that "it only
# runs rm" is how an unpinned image gets into a repository with a rule
# against them. The rule was written down in one file and not followed in
# the four next to it.
#
# So the claim is now checked rather than asserted. That is the whole point:
# a stated invariant nothing verifies is a comment.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

failures=0
fail() { printf '  UNPINNED  %s\n' "$*" >&2; failures=$((failures + 1)); }

echo "==> Dockerfile FROM lines"
# Complete and unambiguous: every build stage must name a digest. `FROM x AS
# y` and plain `FROM x` are both covered because the test is on the whole
# line containing the reference.
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
done < <(grep -rn "^FROM " --include="*Dockerfile*" . 2>/dev/null | sed 's/^\.\///' | cut -d: -f1,3-)

echo
echo "==> upstream images referenced from scripts and workflows"
# Not a shell parser -- a list of the upstream names this repository actually
# uses. A name here without @sha256: on the same line is a finding. Adding a
# new upstream image means adding it here too, which is the point: the
# check should not silently stop covering things.
UPSTREAM='alpine|golang|debian|registry|ubuntu|aquasec/trivy|semgrep/semgrep|zricethezav/gitleaks|ghcr\.io/opentofu/opentofu|gcr\.io/distroless'
while IFS= read -r hit; do
    case "$hit" in
        *"@sha256:"*) continue ;;
        # A comment is prose about an image, not a use of one.
        *"#"*) continue ;;
    esac
    fail "$hit"
done < <(grep -rnE "(^|[^A-Za-z0-9_./-])($UPSTREAM):[A-Za-z0-9._-]+" \
            --include="*.sh" --include="*.yml" --include="*.yaml" \
            ci/ deploy/ .github/ 2>/dev/null \
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
