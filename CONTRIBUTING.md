# Contributing

This project is a reference implementation and a portfolio piece. It is
built to ordinary contribution standards.

## Workflow

1. Create a feature branch off `main` (`feat/...`, `fix/...`, `docs/...`).
2. Make one focused change. Keep PRs small. A single piece of work may be
   several of them.
3. Write or update tests. The coverage floor is 70%.
4. Run the CI gates locally before pushing. Every gate is a script in
   `ci/`, run the same way here and in the pipeline, so a red check is
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
   tools/check-public-links.sh                        # every relative link resolves
   ```

   `ci/verify-release.sh` needs the three anchor inputs in the environment.
   The README lists them.

   These are the gates the pipeline runs. A check that cannot be run from
   here does not belong in the workflow.
5. Open a PR. In the description, include a short **reasoning note** for any
   architectural decision: what you decided, the alternatives, and why.

## The signing and publishing scripts

These are not gates. They need a token, a registry, or both. They are the
same commands the pipeline uses.

```sh
# One-time: provision local signing keys and publish the key inventory.
# Writes only public material to docs/keys/. No private key is written.
deploy/docker/provision-signing-keys.sh

# Fetch and verify cosign. Two tracks, and they are not interchangeable.
# v2 signs and attests images with the PKCS#11 key (the layout admission
# reads). v3 signs keyless and signs release artifacts.
HSM_PKI_COSIGN_VERSION=v2 ci/cosign.sh fetch
HSM_PKI_COSIGN_VERSION=v3 ci/cosign.sh fetch

# Sign a blob or an image over the HSM. Both refuse to leave a signature the
# published public key cannot verify.
COSIGN_PKCS11_PIN=... ci/sign-artifact.sh <file>
COSIGN_PKCS11_PIN=... ci/sign-image.sh <image>@sha256:<digest>

# The PKCS#11 signing mechanism, end to end, against a throwaway registry.
# The publish job runs this before it pushes anything.
ci/signing-mechanism-test.sh <local-image-tag> <sbom.cdx.json>

# Re-check everything the mechanism test signed, holding no key material.
ci/verify-run-artifacts.sh <keys-dir> <binary> <bundle> <image>@sha256:<digest>

# Counter-sign a published digest with image-signing-key-v1 and re-attest
# its SBOM and provenance with the same key. Maintainer-only.
COSIGN_PKCS11_PIN=... ci/countersign-release.sh <image>@sha256:<digest>
```

`ci/publish-image.sh` runs only in the pipeline. It needs the GitHub OIDC
token for keyless signing and the `GITHUB_*` variables the provenance
predicate records. `ci/generate-provenance.sh` refuses without them. A
provenance predicate filled in on a laptop signs as well as a true one.

## Commit messages

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
`chore:`, `ci:`. One logical change per commit.

## Running tests locally

`internal/pkcs11`'s test suite needs a real SoftHSM2 PKCS#11 module. Unit
tests that need no token run regardless. Build and use the dev container
rather than installing SoftHSM2 on your host:

```sh
docker build -t hsm-pki-dev -f ci/softhsm2-dev.Dockerfile .
docker run --rm -v "$PWD:/repo" -w /repo hsm-pki-dev \
  go test ./... -race -cover
```

Running `go test` on a host without SoftHSM2 still passes. The token
tests skip themselves with a message. That skip means you have not run
them.

The cross-vendor behavioral suite lives in `TestConformance`
(`internal/pkcs11/conformance_test.go`) and runs against every backend the
environment can reach:

```sh
go test ./internal/pkcs11 -run TestConformance -race -v
```

With only SoftHSM2 available, its subtests run and ProtectServer's skip. If
you have your own ProtectToolkit-C entitlement, set `PROTECTSERVER_MODULE`
and the workspace and PIN variables listed below to run that backend as
well. Never in CI, always locally, against your own SDK. The maintainer runs
ProtectToolkit-C 7.3.3 in software emulation.

`internal/ca`'s **ceremony** suite follows the same pattern but needs two
tokens. The root and the intermediate live on separate tokens:

```sh
go test ./internal/ca -run TestRunCeremony -race -v
```

For ProtectServer it takes `PROTECTSERVER_MODULE`,
`PROTECTSERVER_ROOT_WORKSPACE`, `PROTECTSERVER_INTERMEDIATE_WORKSPACE`,
`PROTECTSERVER_ROOT_PIN` and `PROTECTSERVER_INTERMEDIATE_PIN`. With any of
them unset those subtests skip. Provisioning the two tokens is a one-time
manual step with the ProtectToolkit tools (`ctconf`, `ctkmu`).

Both backends can run in one invocation by mounting the ProtectToolkit
module and its token store into the dev container. `docs/test-matrix.md` §6
has the command. Run it before opening a PR that touches `internal/pkcs11`
or `internal/ca`. The two backends have disagreed before, and a green
SoftHSM2-only run does not show they still agree.

## Running the service locally

Tests prove the packages. This proves the deployed shape. One command builds
the image, initializes two SoftHSM2 tokens, runs the offline root ceremony
against them, moves the root's token out of the store the service can
reach, and starts the containerized service read-only and non-root:

```sh
deploy/docker/run-local.sh          # --reset to discard the local state first
```

Before you debug it:

- **No PKCS#11 module is inside the image.** Every module is mounted at run
  time. `failed to load module` means the mount is wrong. On Debian, mount
  the target of `/usr/lib/softhsm/libsofthsm2.so`, not the symlink.
- **Only two paths are writable**: `/var/lib/hsm-pki` (the CA store) and
  `/var/lib/softhsm/tokens`. The container runs `--read-only`. If something
  new needs to write, that is a design question.
- **The local state lives in `.local/`**, which is excluded from git and
  from the Docker build context. It holds token directories, which hold
  private keys.

`deploy/docker/README.md` has the mount contract and what has been run
against each backend.

## Coverage floor

The 70% floor is enforced by `ci/coverage.sh`:

```sh
docker run --rm -v "$PWD:/repo" -w /repo hsm-pki-dev bash ci/coverage.sh -race
```

A vendor adapter that needs a proprietary SDK this pipeline does not have
goes in `ci/coverage-exclude.txt`. Its correctness is checked by
`TestConformance` passing against that vendor's module in the maintainer's
own environment (ProtectToolkit-C software emulation today). A bare
`go test -cover` works for a quick local read. The floor is
`ci/coverage.sh`'s number.

## Accepting a Semgrep finding

Exceptions are `nosemgrep` comments in the source, pinned to the rule and
the line, with the reason beside them. Never a disabled ruleset, never a
path exclusion. The directive must be the **last** comment line directly
above the match. A reason block between them stops it suppressing. The
exemption covers that line only, so a second use of the same pattern in the
same file still fails the scan.

## Accepting a vulnerability finding

`ci/scan-deps.sh` and `ci/scan-image.sh` fail on any HIGH or CRITICAL. When
a finding does not apply, add an entry to `ci/vuln-allowlist.yaml` with the
identifier, a statement of why, and an `expired_at` date at most 180 days
out. `ci/vuln-gate` refuses an entry missing any of those, including one
with no expiry, which trivy alone would honour forever. On the expiry date
the finding comes back and somebody looks again. Never edit a scanner's
severity threshold to make a finding go away.

## Non-negotiables

- No secrets in commits or history. `gitleaks` scans every commit on every
  PR and push. The check is required on `main`, so a finding blocks the
  merge, for the repository owner too.
- Private keys and PINs never hit plaintext disk or logs.
- Standard-library crypto. `miekg/pkcs11` for PKCS#11. No hand-rolled
  crypto.
- Develop and test against SoftHSM2. Vendor backends are exercised only
  against modules and tokens the maintainer owns, never an employer's.
- All code, comments, and commit messages in English.

The checks in `ci/` enforce the above. Run them before you push.
