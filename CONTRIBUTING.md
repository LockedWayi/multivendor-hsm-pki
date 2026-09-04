# Contributing

Thanks for looking at this project. It is primarily a portfolio/reference
implementation, but it is built to real contribution standards.

## Workflow
1. Create a feature branch off `main` (`feat/...`, `fix/...`, `docs/...`).
2. Make one focused change. Keep PRs small — one phase may be several PRs.
3. Write or update tests. The coverage floor is 70%.
4. Ensure all CI gates pass locally where possible (`semgrep`, `trivy`,
   `gitleaks`, `tfsec`, `go test`).
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
you have your own ProtectToolkit entitlement (see
`docs/protectserver-setup.md`), set `PROTECTSERVER_MODULE` (and
`PROTECTSERVER_WORKSPACE`, `PROTECTSERVER_PIN`) to also run that backend's
subtests — never in CI, always locally, against your own SDK.

`internal/ca`'s **ceremony** suite follows the same two-backend pattern but
needs *two* tokens rather than one, because the root and the intermediate
live on separate tokens by design:

```sh
go test ./internal/ca -run TestRunCeremony -race -v
```

For ProtectServer it takes its own variables —
`PROTECTSERVER_ROOT_WORKSPACE`, `PROTECTSERVER_INTERMEDIATE_WORKSPACE`, and a
PIN for each. With any of them unset those subtests skip. Provisioning the
second token is a one-time manual step; `docs/protectserver-setup.md` §3b has
the commands.

Both backends can run in one invocation by mounting the ProtectToolkit module
and its token store into the dev container — see `docs/protectserver-setup.md`
§5. That is how the Phase 3b results were produced, and it is worth doing
before opening a PR that touches `internal/pkcs11` or `internal/ca`: the two
backends have disagreed before, and a green SoftHSM2-only run does not tell
you they still agree.

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
it cannot execute (CLAUDE.md §2.3). A bare `go test -cover` still works for a
quick local read, but the floor itself is `ci/coverage.sh`'s number.

## Non-negotiables
- No secrets in commits or history. `gitleaks` blocks merge.
- Private keys and PINs never hit plaintext disk or logs.
- Standard-library crypto; `miekg/pkcs11` for PKCS#11 — no hand-rolled crypto.
- Develop and test against SoftHSM2 — never against employer hardware.
- All code, comments, and commit messages in English.

See `CLAUDE.md` for the full engineering contract.
