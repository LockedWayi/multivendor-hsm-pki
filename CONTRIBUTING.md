# Contributing

Thanks for looking at this project. It is primarily a portfolio/reference
implementation, but it is built to real contribution standards.

## Workflow
1. Create a feature branch off `main` (`feat/...`, `fix/...`, `docs/...`).
2. Make one focused change. Keep PRs small; a single piece of work may be
   several of them.
3. Write or update tests. The coverage floor is 70%.
4. Run the CI gates locally before pushing. Every one of them is a script
   in `ci/`, run the same way here and in the pipeline, so a red check is
   reproducible without pushing again:

   ```sh
   docker run --rm -v "$PWD:/repo" -w /repo hsm-pki-dev go test -race -p 1 ./...
   docker run --rm -v "$PWD:/repo" -w /repo hsm-pki-dev bash ci/coverage.sh -race -p 1
   ci/scan-code.sh                                    # semgrep (SAST)
   ci/scan-secrets.sh                                 # gitleaks over the full history
   ci/scan-deps.sh                                    # trivy fs + govulncheck
   docker build -f deploy/docker/Dockerfile -t hsm-pki-server:local .
   ci/scan-image.sh hsm-pki-server:local              # trivy image + SBOM
   ci/terraform-scan.sh                               # tofu fmt/validate + trivy
   ci/check-image-pins.sh                             # every image pinned by digest
   ci/assert-publishable-selftest.sh                  # the publish guard, both ways
   ci/verify-release.sh --inventory-only              # anchor + key inventory
   ```

   These are every gate the pipeline runs, in the order it runs them. That is
   the point of the list: CI is not a second environment to keep in sync, so
   a check that cannot be run from here does not belong in the workflow.

## The signing and publishing scripts

Not gates — they need a token, a registry, or both — but they are the same
commands the pipeline uses, and they are here so the pipeline is not the only
place they exist.

```sh
# One-time: provision local signing keys and publish the key inventory.
# Writes only public material to docs/keys/; no private key is ever written.
deploy/docker/provision-signing-keys.sh

# Fetch and verify cosign. Two tracks, and they are not interchangeable:
# v2 signs and attests images (the layout admission reads), v3 signs release
# artifacts (its bundle is what internal/artifactsig reads, and the flag that
# suppresses the transparency log exists only there).
HSM_PKI_COSIGN_VERSION=v2 ci/cosign.sh fetch
HSM_PKI_COSIGN_VERSION=v3 ci/cosign.sh fetch

# Sign a blob or an image over the HSM. Both refuse to leave a signature the
# published public key cannot verify.
COSIGN_PKCS11_PIN=... ci/sign-artifact.sh <file>
COSIGN_PKCS11_PIN=... ci/sign-image.sh <image>@sha256:<digest>

# Build, scan, push and sign, exactly as the publish job does. Needs a
# registry login and the GITHUB_* variables the provenance predicate records.
COSIGN_PKCS11_PIN=... ci/publish-image.sh <registry>/<repo>

# Re-check everything a run signed, from somewhere holding no key material.
ci/verify-run-artifacts.sh <keys-dir> <binary> <bundle> <image>@sha256:<digest>

# Give a published digest a signature a stranger can act on. Maintainer-only:
# it uses the durable key, not the pipeline's ephemeral one.
COSIGN_PKCS11_PIN=... ci/countersign-release.sh <image>@sha256:<digest>
```

`ci/generate-provenance.sh` is deliberately not runnable by hand: it refuses
without the `GITHUB_*` environment, because a provenance predicate filled in
on a laptop signs exactly as well as a true one and a reader cannot tell them
apart.

5. Open a PR. In the description, include a short **reasoning note** for any
   architectural decision: what you decided, the alternatives, and why.

## Commit messages
Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`,
`ci:`. One logical change per commit.

## Running tests locally
`internal/pkcs11`'s test suite needs a real SoftHSM2 PKCS#11 module to run
its integration tests against (unit tests that need no hardware run
regardless). Build and use the provided dev container rather than
installing SoftHSM2 on your host:

```sh
docker build -t hsm-pki-dev -f ci/softhsm2-dev.Dockerfile .
docker run --rm -v "$PWD:/repo" -w /repo hsm-pki-dev \
  go test ./... -race -cover
```

Running `go test` directly on a host without SoftHSM2 installed still
passes — the integration tests skip themselves with an explanatory message
rather than failing — but that skip means you have not actually run them.

The cross-vendor behavioral suite lives in `TestConformance`
(`internal/pkcs11/conformance_test.go`) and runs against every backend the
environment can reach:

```sh
go test ./internal/pkcs11 -run TestConformance -race -v
```

With only SoftHSM2 available, its subtests run and ProtectServer's skip. If
you have your own ProtectToolkit-C entitlement, set `PROTECTSERVER_MODULE`
and the workspace and PIN variables listed below to run that backend's
subtests as well. Never in CI, always locally, against your own SDK. The
maintainer runs ProtectToolkit-C 7.3.3 in software emulation.

`internal/ca`'s **ceremony** suite follows the same two-backend pattern but
needs *two* tokens rather than one, because the root and the intermediate
live on separate tokens by design:

```sh
go test ./internal/ca -run TestRunCeremony -race -v
```

For ProtectServer it takes `PROTECTSERVER_MODULE`,
`PROTECTSERVER_ROOT_WORKSPACE`, `PROTECTSERVER_INTERMEDIATE_WORKSPACE`,
`PROTECTSERVER_ROOT_PIN` and `PROTECTSERVER_INTERMEDIATE_PIN`. With any of
them unset those subtests skip. Provisioning the two tokens is a one-time
manual step with the ProtectToolkit tools (`ctconf`, `ctkmu`).

Both backends can run in one invocation by mounting the ProtectToolkit
module and its token store into the dev container; `docs/test-matrix.md`
§6 has the command. Run it before opening a PR that touches
`internal/pkcs11` or `internal/ca`. The two backends have disagreed before,
and a green SoftHSM2-only run does not show they still agree.

## Running the service locally

Tests prove the packages; this proves the deployed shape. One command builds
the image, initializes two SoftHSM2 tokens, runs the real offline root
ceremony against them, takes the root's token out of the store the service
can reach, and starts the containerized service read-only and non-root:

```sh
deploy/docker/run-local.sh          # --reset to discard the local state first
```

Worth knowing before you debug it:

- **No PKCS#11 module is inside the image.** Every module is mounted at run
  time, so `failed to load module` means the mount is wrong, not the build.
  On Debian, mount the *target* of `/usr/lib/softhsm/libsofthsm2.so`, not the
  symlink.
- **Only two paths are writable**, `/var/lib/hsm-pki` (the CA store) and
  `/var/lib/softhsm/tokens`. The container runs `--read-only`; if something
  new needs to write, that is a design question, not a mount to add
  reflexively.
- **The local state lives in `.local/`**, which is excluded from git *and*
  from the Docker build context — it holds token directories, which hold
  private keys.

`deploy/docker/README.md` has the mount contract and what has actually been
run against each backend.

## Coverage floor
The 70% floor is enforced by `ci/coverage.sh`, not a bare `go test -cover`:

```sh
docker run --rm -v "$PWD:/repo" -w /repo hsm-pki-dev bash ci/coverage.sh -race
```

The difference matters once a vendor adapter needs a proprietary SDK or real
hardware this pipeline does not have: that adapter's file goes in
`ci/coverage-exclude.txt`, and its correctness is validated by
`TestConformance` passing against real hardware in the maintainer's own
environment instead of by a percentage CI cannot honestly compute for code
it cannot execute. A bare `go test -cover` still works for a
quick local read, but the floor itself is `ci/coverage.sh`'s number.

## Accepting a Semgrep finding
Exceptions are `nosemgrep` comments in the source, pinned to the rule and the
line, with the reason written beside them — never a disabled ruleset, never a
path exclusion. Two things to know: the directive must be the **last** comment
line directly above the match (a reason block between them silently stops it
suppressing), and the exemption covers that line only, so a second use of the
same pattern in the same file still fails the scan. That is deliberate.

## Accepting a vulnerability finding
`ci/scan-deps.sh` and `ci/scan-image.sh` fail on any HIGH or CRITICAL. When a
finding genuinely does not apply, it is *accepted*, not silenced: add an entry
to `ci/vuln-allowlist.yaml` with the identifier, a statement of why, and an
`expired_at` date at most 180 days out. `ci/vuln-gate` refuses an entry
missing any of those — including one with no expiry, which trivy alone would
honour forever. On the expiry date the finding comes back on its own and
somebody looks again. Never edit a scanner's severity threshold to make a
finding go away.

## Non-negotiables
- No secrets in commits or history. `gitleaks` scans every commit on every
  PR and push. The check is required on `main`, so a finding blocks the
  merge, for the repository owner too.
- Private keys and PINs never hit plaintext disk or logs.
- Standard-library crypto; `miekg/pkcs11` for PKCS#11 — no hand-rolled crypto.
- Develop and test against SoftHSM2. Vendor backends are exercised only
  against hardware the maintainer owns.
- All code, comments, and commit messages in English.

Everything above is enforced by the checks in `ci/`, not by convention alone —
run them before you push and a review starts from working code.
