# shellcheck shell=bash
#
# Resolve which key a signer must use, from the signed key inventory.
# Sourced, never executed:
#
#   . "$REPO_ROOT/ci/active-signing-key.sh"
#   KEY_LABEL="$(activeSigningKey image "$KEYS_DIR")"
#
# Why this exists. ci/select-key has had -active-only since it was
# written -- "select keys a signer may use, not keys a verifier may
# accept" -- and until now nothing called it. Every signer named its key
# as a constant or an environment default: image-signing-key-v1,
# artifact-signing-key-v1. The verifiers already read the inventory, so
# the two halves disagreed about where the answer lives.
#
# That shape is what a rotation runs into. Provisioning -v2 and marking
# -v1 verify-only is the documented routine, and with a constant in the
# signer the cutover is a code change to four scripts. A rotation that
# needs a code change is a rotation that does not happen.
#
# Fail-closed rules, both of them deliberate:
#
#   no active key    -- refuse. A purpose whose key is verify-only or
#                       retired has nothing to sign with, and picking a
#                       verify-only key would sign with a key the
#                       inventory says is on its way out.
#   two active keys  -- refuse. Choosing between them would be
#                       enumeration order making a key decision, which is
#                       nobody's decision. Two active keys for one purpose
#                       is a state the inventory should not be in, and
#                       signing anyway would hide it.
#
# HSM_PKI_<PURPOSE>_KEY_LABEL still works, for a drill or an emergency,
# but it is checked rather than obeyed: the label it names must be one the
# inventory lists as active. An override that can disagree with the
# inventory is a second source of truth, and the signature would be made
# under a key the published document does not vouch for.

# activeSigningKey <purpose> <keys-dir> prints the label to sign with.
activeSigningKey() {
    local purpose="$1" keys_dir="$2" repo_root inv_rel override_var override lines count label
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    case "$keys_dir" in
        "$repo_root"/*) inv_rel="${keys_dir#"$repo_root"/}/key-inventory.json" ;;
        *)
            echo "active-signing-key: the keys directory must be inside $repo_root; got $keys_dir" >&2
            return 1 ;;
    esac
    if [ ! -f "$repo_root/$inv_rel" ]; then
        echo "active-signing-key: no inventory at $inv_rel. A signer takes its key from the" >&2
        echo "active-signing-key: published inventory, so there is nothing to sign with until one exists." >&2
        return 1
    fi

    # select-key reads valid_from, valid_until, retired_at and status. The
    # signature over the inventory is not checked here: a signer is inside
    # the trust boundary that produced it, and the verifiers that are not
    # check it with openssl before they read it.
    #
    # stderr is kept separate rather than folded in with 2>&1, and the
    # output is then filtered to the lines that carry select-key's tab
    # separator. Both are needed, and the first was learned the hard way:
    # when the builder image is not already present, docker's pull
    # progress lands in the capture, and counting it reported twelve
    # active keys where there is one. It passed locally, where the image
    # was warm, and failed on a cold runner.
    local err
    err="$(mktemp)"
    if ! lines="$(goRun ./ci/select-key -inventory "/repo/$inv_rel" -purpose "$purpose" -active-only 2>"$err")"; then
        echo "active-signing-key: no key the inventory lists as active for purpose '$purpose':" >&2
        cat "$err" >&2
        rm -f "$err"
        return 1
    fi
    rm -f "$err"
    # label<TAB>status<TAB>path. Anything without a tab is not a selection.
    lines="$(printf '%s\n' "$lines" | grep -F "$(printf '\t')" || true)"

    count="$(printf '%s\n' "$lines" | grep -c . || true)"
    if [ "$count" != "1" ]; then
        echo "active-signing-key: the inventory lists $count active '$purpose' keys; it must list exactly one." >&2
        echo "active-signing-key: choosing between them would make enumeration order the key decision." >&2
        printf '%s\n' "$lines" | sed 's/^/    /' >&2
        return 1
    fi
    label="$(printf '%s\n' "$lines" | cut -f1)"

    override_var="HSM_PKI_$(printf '%s' "$purpose" | tr '[:lower:]' '[:upper:]')_KEY_LABEL"
    override="${!override_var:-}"
    if [ -n "$override" ] && [ "$override" != "$label" ]; then
        echo "active-signing-key: $override_var names '$override', which the inventory does not list as the" >&2
        echo "active-signing-key: active '$purpose' key -- it lists '$label'. The override exists to be checked," >&2
        echo "active-signing-key: not to win: a signature under a key the published inventory does not vouch for" >&2
        echo "active-signing-key: verifies for nobody." >&2
        return 1
    fi

    printf '%s\n' "$label"
}
