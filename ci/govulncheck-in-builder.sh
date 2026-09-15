#
# The govulncheck half of the dependency gate, run inside the digest-pinned
# builder image with the repository mounted at /repo. ci/scan-deps.sh
# invokes it as `sh /repo/ci/govulncheck-in-builder.sh`; it is not meant to
# be run on a host, which is why it carries no execute bit.
#
# Inputs, supplied by ci/scan-deps.sh as environment variables:
#
#   GOVULNCHECK_VERSION  the module version to install, from ci/scanner-pins.sh
#   ALLOWLIST            repo-relative path to the shared vulnerability allowlist
#
# Why a file and not the inline `sh -c "..."` this was until 2026-09-15:
# the inline form was a multi-line double-quoted bash string, so a bare `"`
# anywhere inside it -- in prose as readily as in code -- closed the string
# early and handed `sh` whatever came before it. That is what happened. A
# comment rewritten to say Plain "go mod download" cut the script off
# mid-comment, three lines after `go install`, so govulncheck, the module
# download and ci/vuln-gate never ran. The truncated script exited 0, the
# gate printed "clean: no blocking dependency vulnerabilities", and the
# required check was green for five days over a scan that had not happened.
# A file cannot be cut short by a quote.
set -e

: "${GOVULNCHECK_VERSION:?govulncheck-in-builder: GOVULNCHECK_VERSION is not set}"
: "${ALLOWLIST:?govulncheck-in-builder: ALLOWLIST is not set}"

# The checkout is owned by the invoking user and this container runs as root.
git config --global --add safe.directory /repo

# Retry the steps that reach the network, and only those. A module proxy
# reset is not a finding. The scan itself is not retried.
retry() {
    attempt=1
    while true; do
        if "$@"; then return 0; fi
        if [ "$attempt" -ge 3 ]; then
            echo "govulncheck-in-builder: '$*' failed after $attempt attempts" >&2
            return 1
        fi
        echo "govulncheck-in-builder: '$*' failed, retrying ($attempt/3)" >&2
        sleep $((attempt * 5))
        attempt=$((attempt + 1))
    done
}

retry go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"

# The module cache is filled first, where a proxy failure is retried; inside
# govulncheck's loader the same failure reads as a broken dependency. Plain
# "go mod download", not "go mod download all": the "all" pattern writes the
# checksums of test dependencies of dependencies into go.sum and leaves the
# checkout dirty.
retry go mod download

# -format json, because text cannot be filtered against the allowlist. Test
# files are out of scope: the question is what the shipped binary reaches.
# govulncheck -format json exits 0 even on a called vulnerability, so
# ci/vuln-gate is what turns its findings into an exit status.
"$(go env GOPATH)"/bin/govulncheck -format json ./... > /tmp/govulncheck.json
go run ./ci/vuln-gate -govulncheck /tmp/govulncheck.json -allowlist "${ALLOWLIST}"

# Deliberately the last line, and ci/scan-deps.sh fails the run without it.
# A stage that stops early exits 0 and prints nothing alarming, which is
# indistinguishable from a clean scan by exit status alone -- exactly the
# defect above. So the evidence that the work happened is in the output,
# not inferred from a zero.
echo "govulncheck-in-builder: complete, ${GOVULNCHECK_VERSION} ran and ci/vuln-gate judged its findings"
