#!/usr/bin/env bash
#
# Prove ci/active-signing-key.sh refuses what it says it refuses.
#
#   ci/active-signing-key-selftest.sh
#
# Every case here is a refusal except the last two. A resolver nobody has
# watched refuse is a resolver whose guards are decoration: the failure
# modes it exists for -- no active key, two active keys, an override that
# disagrees with the published document -- all end in a signature made
# under a key the inventory does not vouch for, which verifies for nobody.
#
# It builds throwaway inventories under .local/, which is gitignored, and
# derives them from the published one so the schema stays honest. If the
# inventory format changes, these fixtures stop parsing and this fails.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=ci/scanner-pins.sh
. "$REPO_ROOT/ci/scanner-pins.sh"
# shellcheck source=ci/active-signing-key.sh
. "$REPO_ROOT/ci/active-signing-key.sh"

WORK="$REPO_ROOT/.local/active-key-selftest"
rm -rf "$WORK"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0

# refuses <expected substring> <name> -- the resolver must fail, and say why.
refuses() {
    local want="$1" name="$2"; shift 2
    local out status
    out="$("$@" 2>&1)"; status=$?
    if [ "$status" -eq 0 ]; then
        printf '  FAIL  %-52s (resolved %s, wanted a refusal)\n' "$name" "$out"
        fail=$((fail+1)); return
    fi
    if ! printf '%s' "$out" | grep -qF "$want"; then
        printf '  FAIL  %-52s (refused, but not for the stated reason)\n' "$name"
        printf '        wanted: %s\n' "$want"
        printf '        %s\n' "${out//$'\n'/$'\n'        }"
        fail=$((fail+1)); return
    fi
    printf '  ok    %-52s (refused, for the stated reason)\n' "$name"
    pass=$((pass+1))
}

# resolves <expected label> <name> -- the resolver must print exactly that.
resolves() {
    local want="$1" name="$2"; shift 2
    local out status
    out="$("$@" 2>&1)"; status=$?
    if [ "$status" -ne 0 ] || [ "$out" != "$want" ]; then
        printf '  FAIL  %-52s (wanted %s, got %s)\n' "$name" "$want" "${out//$'\n'/ }"
        fail=$((fail+1)); return
    fi
    printf '  ok    %-52s (%s)\n' "$name" "$out"
    pass=$((pass+1))
}

PUBLISHED="$REPO_ROOT/docs/keys/key-inventory.json"
[ -f "$PUBLISHED" ] || { echo "active-signing-key-selftest: no published inventory to derive fixtures from" >&2; exit 1; }

# A: no inventory at all.
mkdir -p "$WORK/empty"
refuses "no inventory at" "A1 a keys directory with no inventory" \
    activeSigningKey image "$WORK/empty"

# B: a keys directory outside the repository.
refuses "must be inside" "B1 a keys directory outside the repository" \
    activeSigningKey image /tmp

# C: the published inventory resolves, and the override is accepted only
#    when it agrees with it.
resolves "image-signing-key-v1" "C1 the published inventory names one active image key" \
    activeSigningKey image "$REPO_ROOT/docs/keys"
resolves "artifact-signing-key-v1" "C2 and one active artifact key" \
    activeSigningKey artifact "$REPO_ROOT/docs/keys"
# Derived from the label the inventory actually lists rather than written
# out, for two reasons. It stays plausible as the inventory moves, and a
# literal supply-chain key label in a shell script is exactly what
# internal/keyaudit refuses -- correctly: a file that instructs a machine
# to sign with a key the published inventory does not list is a defect,
# and that rule is directional so it carries no exemption list. A fixture
# should not be the reason to weaken it.
NOT_LISTED="$(activeSigningKey image "$REPO_ROOT/docs/keys")-is-not-this-key"
refuses "which the inventory does not list as the" "C3 an override the inventory does not list" \
    env HSM_PKI_IMAGE_KEY_LABEL="$NOT_LISTED" \
        bash -c '. "$0/ci/scanner-pins.sh"; . "$0/ci/active-signing-key.sh"; activeSigningKey image "$0/docs/keys"' "$REPO_ROOT"

# D: two active keys for one purpose. Derived with a genuinely different
#    key pair, because the inventory's own validation catches the same key
#    under two labels first and would hide this branch.
mkdir -p "$WORK/two-active"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/k.pem" 2>/dev/null
python3 - "$PUBLISHED" "$WORK/two-active/key-inventory.json" "$WORK/k.pem" <<'PY'
import copy, json, pathlib, subprocess, sys
src, dst, keyfile = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.loads(pathlib.Path(src).read_text())
img = next(k for k in d["keys"] if k["purpose"] == "image" and k["status"] == "active")
pub = subprocess.run(["openssl", "ec", "-in", keyfile, "-pubout"],
                     check=True, capture_output=True, text=True).stdout
second = copy.deepcopy(img)
second["label"] = img["label"].rsplit("-v", 1)[0] + "-v2"
second["public_key"] = pub
d["keys"].append(second)
pathlib.Path(dst).write_text(json.dumps(d, indent=2))
PY
refuses "it must list exactly one" "D1 two active keys for one purpose" \
    activeSigningKey image "$WORK/two-active"

# E: no active key, only a verify-only one. This is the state a rotation
#    leaves behind between provisioning the next version and cutting over,
#    and signing with a key on its way out is what must not happen.
mkdir -p "$WORK/verify-only"
python3 - "$PUBLISHED" "$WORK/verify-only/key-inventory.json" <<'PY'
import json, pathlib, sys
d = json.loads(pathlib.Path(sys.argv[1]).read_text())
for k in d["keys"]:
    if k["purpose"] == "image":
        k["status"] = "verify-only"
pathlib.Path(sys.argv[2]).write_text(json.dumps(d, indent=2))
PY
refuses "no key the inventory lists as active" "E1 only a verify-only key for the purpose" \
    activeSigningKey image "$WORK/verify-only"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
