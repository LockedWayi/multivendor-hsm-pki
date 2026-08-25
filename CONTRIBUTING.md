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

## Non-negotiables
- No secrets in commits or history. `gitleaks` blocks merge.
- Private keys and PINs never hit plaintext disk or logs.
- Standard-library crypto; `miekg/pkcs11` for PKCS#11 — no hand-rolled crypto.
- Develop and test against SoftHSM2 — never against employer hardware.
- All code, comments, and commit messages in English.

See `CLAUDE.md` for the full engineering contract.
