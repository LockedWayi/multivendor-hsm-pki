---
project: multivendor-hsm-pki
status: parked
phase: ""
phase_status: not started
next: >-
  Resume when a test HSM is available; first action: re-run the Luna
  conformance suite and compare with docs/test-matrix.md.
blocked_on: "A test HSM (Luna or nShield) is needed for the next test"
needs_owner: false
needs_owner_why: ""
updated: 2026-10-02
---

# Progress

**Parked on 2026-10-02.** The project is near finished and waits for a
test HSM: the next step is the third and fourth backends (Luna, nShield),
and the conformance suite cannot run against them on this machine. The
phase plan lives in the private companion repository, hsm-pki-platform;
this repository has no `docs/phases/`, so the frontmatter names no phase.
What runs where, and what was measured on which backend, is in
[docs/test-matrix.md](test-matrix.md). Nothing else changes while parked.
