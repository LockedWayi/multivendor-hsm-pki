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

<!--
Tag v0.1.0 once Phase 1 (PKCS#11 core) lands. Each phase producing a user-visible
capability bumps at least the minor version.
-->
