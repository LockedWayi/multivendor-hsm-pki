#!/usr/bin/env bash
#
# Scan every commit for secrets with gitleaks, as the pipeline does.
#
#   ci/scan-secrets.sh
#
# The subject is the history, not the working tree. A shallow clone would
# scan only the tip, so one is refused. Exceptions live in .gitleaks.toml
# and .gitleaksignore, each with its reason.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "${SCRIPT_DIR}/scanner-pins.sh"

if [ "$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository)" = "true" ]; then
    echo "scan-secrets: this is a shallow clone, so the scan would cover only the tip." >&2
    echo "Fetch the full history first: git fetch --unshallow" >&2
    exit 1
fi

# The GIT_CONFIG_* variables tell git inside the container that the
# checkout, owned by another uid, is safe to read.
docker run --rm -v "$REPO_ROOT":/repo -w /repo \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0='*' \
    "$GITLEAKS_IMAGE" \
    git . --config .gitleaks.toml

echo
echo "==> clean: no secrets in any commit"
