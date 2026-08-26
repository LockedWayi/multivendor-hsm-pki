# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
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
