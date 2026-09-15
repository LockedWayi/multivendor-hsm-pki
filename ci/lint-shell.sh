#!/usr/bin/env bash
#
# Run shellcheck over every shell script this repository tracks.
#
#   ci/lint-shell.sh
#
# Every gate in the pipeline is a shell script, and until this existed
# nothing read them for the mistakes shellcheck catches. The tool was
# installed in the development environment and invoked by nothing, which
# is the shape of defect this repository keeps finding in itself: a check
# that is present, and therefore assumed to run.
#
# Warning and above fail; info and style are reported nowhere, so a
# finding here is one worth a change. -x follows the files a script
# sources, and the sourced files carry a `shell=bash` directive because a
# sourced file has no shebang by design. Exceptions are `disable`
# directives on the line they cover, each with its reason beside it.
#
# The scripts inside workflow `run:` blocks are not covered: they are YAML
# strings, not files. Keep them to one call of a script under ci/.
#
# Pinned by digest to the version installed in the development
# environment (ci/scanner-pins.sh), so passing locally and passing here
# are the same claim.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"
cd "$REPO_ROOT"

# Only files this repository tracks, so a dependency's scripts inside a
# restored cache are not linted.
mapfile -d '' SCRIPTS < <(git ls-files -z -- '*.sh')
[ "${#SCRIPTS[@]}" -gt 0 ] || { echo "lint-shell: git ls-files found no *.sh; refusing to report a clean run over nothing" >&2; exit 1; }

echo "==> shellcheck -x -S warning over ${#SCRIPTS[@]} tracked scripts"
docker run --rm -v "$REPO_ROOT":/repo -w /repo "$SHELLCHECK_IMAGE" \
    -x -S warning -- "${SCRIPTS[@]}"
echo "    clean"
