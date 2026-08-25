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
- `internal/pkcs11/protectserver.go`: `ProtectServerAdapter` skeleton (all
  methods panic; implementation is Phase 1 sub-task 1.7). The compile-time
  interface assertion proves a second, independent vendor satisfies
  `VendorAdapter` without the interface changing.
- `docs/protectserver-setup.md`: manual setup for the Thales ProtectToolkit
  backend — module paths, user-token initialization, and why this path is
  local-only and never in CI.
- First recorded vendor divergence: pointing the SoftHSM2 adapter at the
  ProtectToolkit module showed that session handling, login, key generation,
  signing, and object lookup all transfer unchanged, but `C_Verify` rejects a
  signature `C_Sign` just produced (`CKR_SIGNATURE_INVALID`). Documented in
  `protectserver.go` with candidate causes; diagnosing it is a Phase 1
  sub-task, and it is the concrete evidence that a second vendor was worth
  validating against rather than assuming.

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
