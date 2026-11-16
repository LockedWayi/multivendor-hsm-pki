# shellcheck shell=bash
# Sourced by ci/signing-mechanism-test.sh and ci/rotation-drill.sh, which
# run the same kind of drill against a throwaway registry: one copy of the
# helpers both need. The sourcing script defines die and sets
# REGISTRY_IMAGE (from ci/scanner-pins.sh) first.

# expect_fail <substring> <name> -- <command>: the command must exit
# non-zero and print the substring. A refusal nobody has watched happen
# proves nothing, and one that happens for another reason proves the
# wrong thing.
expect_fail() {
    local want="$1" name="$2"; shift 2
    [ "$1" = "--" ] && shift
    local out status
    out="$("$@" 2>&1)" && status=0 || status=$?
    if [ "$status" -eq 0 ]; then
        printf '%s\n' "$out" >&2
        die "$name: expected a refusal, got exit 0"
    fi
    if ! printf '%s' "$out" | grep -qF "$want"; then
        printf '%s\n' "$out" >&2
        die "$name: refused, but not for the stated reason (wanted '$want')"
    fi
    echo "    refused: $name"
}

# start_registry: a registry on a free loopback port, for one run. Sets
# REGISTRY_CID, which the caller's EXIT trap removes, and REGISTRY.
start_registry() {
    local port
    REGISTRY_CID="$(docker run -d -p 127.0.0.1:0:5000 "$REGISTRY_IMAGE")"
    port="$(docker port "$REGISTRY_CID" 5000/tcp | head -1 | sed 's/.*://')"
    REGISTRY="localhost:$port"
    for _ in $(seq 1 30); do
        curl -fsS "http://$REGISTRY/v2/" >/dev/null 2>&1 && break
        sleep 0.5
    done
    curl -fsS "http://$REGISTRY/v2/" >/dev/null || die "the throwaway registry did not come up on $REGISTRY"
    echo "    $REGISTRY"
}
