#!/usr/bin/env bash
#
# Fail on any relative link in a Markdown file that points at a file which
# does not exist in the tree.
#
#   tools/check-public-links.sh [<tree>]
#
# The tree defaults to the repository this script lives in. The public
# repository is produced from a private one with some files removed, so a
# link that was correct there can point at nothing here. This check runs
# in the suite gate so such a link fails the build.
set -euo pipefail

TREE="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$TREE"

python3 - <<'PY'
import os, re, subprocess, sys

files = subprocess.run(["git", "ls-files", "-z", "--", "*.md"], capture_output=True, check=True).stdout
files = [f for f in files.decode().split("\0") if f]
link = re.compile(r'\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
dead = 0
for f in sorted(files):
    text = open(f, encoding="utf-8").read()
    for m in link.finditer(text):
        target = m.group(2)
        if re.match(r"^(https?:|mailto:|#)", target):
            continue
        path = target.split("#")[0]
        if not path:
            continue
        resolved = os.path.normpath(os.path.join(os.path.dirname(f), path))
        if not os.path.exists(resolved):
            line = text[: m.start()].count("\n") + 1
            print(f"{f}:{line}: [{m.group(1)}]({target}) -> missing {resolved}")
            dead += 1
if dead:
    print(f"check-public-links: {dead} relative link(s) point at files that do not exist", file=sys.stderr)
    sys.exit(1)
print(f"check-public-links: every relative link in {len(files)} Markdown files resolves")
PY
