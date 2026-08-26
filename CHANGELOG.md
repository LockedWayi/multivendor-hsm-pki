# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `internal/ca.CA`, `internal/ca.Bootstrap`: CA domain logic on top of the
  Phase 2 signer. `Bootstrap` decides between loading an existing CA and
  creating a new one by checking two independent signals — an HSM key under
  `ca.key_label` and a certificate file at `ca.cert_path` (new config
  fields) — and refuses to guess when only one is present, rather than risk
  signing under a mismatched key or duplicating a label meant to be unique.
  `Issue` validates a CSR's signature, subject, and key type (EC
  P-256/P-384/P-521 or RSA ≥ 2048 bits) before building a certificate;
  serials are 128 bits of `crypto/rand`, never sequential. Verified with
  `openssl verify` against a real issued certificate, not just Go's own
  `crypto/x509` round trip.
- `internal/ca.Signer`: a `crypto.Signer` backed by an HSM-resident EC key
  pair, reached through `VendorAdapter`. Every `Sign` call opens its own
  session, authenticates, and closes the session again — it never holds one
  for its lifetime (`pkcs11.Session` fails closed on idle timeout / max TTL,
  so a service-lifetime session would eventually start failing every call
  for reasons unrelated to the request). `pkcs11.DecodeECPoint` moved from a
  test-only helper into the `pkcs11` package proper, fixing a long-form DER
  length bug the test-only version had for any EC point ≥128 bytes.
  Verified: `x509.CreateCertificate` produces a certificate over a
  SoftHSM2-resident key, and `cert.CheckSignatureFrom` accepts it.
- `cmd/hsm-pki-server`, `internal/config`, `internal/api`: the Phase 2 service
  skeleton. `internal/config` loads `config.yaml`, validates the selected
  adapter and its module path/workspace label/PIN-env-var name, and fails
  fast on an unknown adapter or a PIN environment variable that isn't set —
  before any HSM call is attempted. The PIN's value itself is never held on
  the `Config` struct; it is read once, at the point of use. `main.go`
  proves the configured adapter can actually open a session and log in
  before serving any traffic, and shuts down gracefully (drain, then close
  the adapter) on `SIGTERM`/`SIGINT`. Verified against both SoftHSM2 and the
  maintainer's ProtectServer token.
- Project scaffolding: `CLAUDE.md` engineering contract, architecture document,
  and phase specifications (Phases 1–7), centered on a multi-vendor PKCS#11 core.
- `internal/pkcs11`: vendor-agnostic `VendorAdapter` interface (session
  open/close, login/logout, key generation, find objects, sign/verify,
  encrypt/decrypt, get attribute, wrap/unwrap, generate random) and a
  SoftHSM2-backed implementation. Sessions enforce an idle timeout and a
  maximum TTL; PINs are held in a C-heap buffer we control and zeroize,
  never as a Go-heap string (see docs/phases/phase-1-pkcs11-core.md).
- `ci/softhsm2-dev.Dockerfile`: reproducible dev/test environment so the
  SoftHSM2-backed test suite runs the same way on any machine or in CI.
- `internal/pkcs11/protectserver.go`: `ProtectServerAdapter`, a full,
  independently-written second implementation of `VendorAdapter` against
  Thales ProtectToolkit-C. Every operation in the interface — session
  lifecycle, key generation, sign/verify, encrypt/decrypt, wrap/unwrap,
  generate random, find/get-attributes, close — is confirmed working
  against the maintainer's own ProtectToolkit installation by the
  conformance suite below.
- `internal/pkcs11/conformance_test.go`: `TestConformance`, one behavioral
  suite parameterized over a `VendorAdapter` factory, run against both
  backends. SoftHSM2's subtests run whenever its module is present (CI);
  ProtectServer's run only when `PROTECTSERVER_MODULE` is set and skip
  cleanly otherwise — the suite stays green either way. Every test vector is
  a real digest, plaintext, or key, never a degenerate stand-in — the earlier
  false "ProtectServer cannot verify" divergence (below) came from exactly
  that shortcut.
- `docs/protectserver-setup.md`: manual setup for the Thales ProtectToolkit
  backend — module paths, user-token initialization, and why this path is
  local-only and never in CI.
- `ci/coverage.sh` and `ci/coverage-exclude.txt`: the coverage floor,
  computed over CI-reachable code only. `ProtectServerAdapter` now contains
  real, non-trivial logic that CI structurally cannot execute (no
  proprietary SDK), so a blanket `go test ./... -cover` no longer measures
  what it used to — it conflates "untested" with "untestable here." The
  excluded files are validated instead by the conformance suite passing
  against real hardware, and that claim stays labelled maintainer-verified,
  never blended into a CI-reported percentage (CLAUDE.md §2.3).
- `docs/pkcs11-vendor-notes.md`: a living record of where PKCS#11
  implementations differ and of the portability traps (`CK_ULONG` width,
  `CKA_EC_POINT` encoding, raw `r||s` signatures, digest-vs-message
  mechanisms) that are easy to write and hard to notice. Every adapter reads
  it before being written and adds to it afterwards.
- First cross-vendor comparison run: pointing the SoftHSM2 adapter at the
  ProtectToolkit module showed the entire exercised surface — sessions, login,
  key generation, signing, verification, object lookup, attributes —
  transfers unchanged. One narrow divergence recorded: ProtectToolkit's
  `C_Verify` rejects a signature over an all-zero digest that its own
  `C_Sign` produced, where SoftHSM2 accepts it. Benign, since a real digest is
  never all-zero.

### Changed
- `internal/pkcs11/base.go`: the shared PKCS#11 plumbing (`pkcs11Adapter`)
  extracted from `SoftHSM2Adapter` and `ProtectServerAdapter` now that both
  have been run against real hardware. Every operation the conformance
  suite exercises turned out to need zero vendor-specific code — the one
  real divergence found (an all-zero-digest `Verify` rejection, ProtectServer
  only) is HSM behavior, not adapter logic, so it stays a documented fact in
  `protectserver.go` rather than a branch. `SoftHSM2Adapter` and
  `ProtectServerAdapter` are now each a named type embedding
  `*pkcs11Adapter` plus a constructor. Phase 1 sub-task 1.8; completes
  Phase 1.
- Phase files now carry a `Sub-tasks` checklist with observable **Done when**
  criteria, so progress mid-phase is readable from the document rather than
  inferred from commit history. All seven phases are broken down; where a
  choice is the maintainer's to make, it is recorded as an explicit
  "Decide before starting" item rather than defaulted silently.
- `CLAUDE.md` §7 gained the tracking discipline this depends on: discovered
  work — prerequisites, workarounds, defects found in passing, work belonging
  to a later phase — is added to the relevant checklist rather than silently
  absorbed, and a decision the agent cannot make blocks its sub-task rather
  than the phase.
- ProtectServer environment prepared: Admin token PINs initialized and a
  labelled user token created on slot 0. `docs/protectserver-setup.md` now
  documents the sequence that actually works, including the mid-run label
  prompt that is easy to answer with a PIN by mistake.
- Phase 1 scope now includes a second, real-vendor adapter (ProtectServer)
  alongside SoftHSM2, and its acceptance criteria are split into CI-verifiable
  and maintainer-verified halves so a reader can tell which claims an automated
  run backs.
- `config.example.yaml` gained per-adapter blocks and now references PINs by
  environment-variable *name* rather than carrying any value.
- README and architecture docs state which vendor backends actually exist
  today rather than implying all four are working.

### Fixed
- `.gitignore` did not exclude `config.yaml`, despite `config.example.yaml`
  stating that it did — the file intended to hold real values was trackable.
  Also added guards against committing proprietary vendor SDK binaries.

<!--
Tag v0.1.0 once Phase 1 (PKCS#11 core) lands. Each phase producing a user-visible
capability bumps at least the minor version.
-->
