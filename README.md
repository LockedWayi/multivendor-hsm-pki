# HSM-PKI Platform

![coverage](docs/coverage.svg)

A vendor-agnostic **PKCS#11 abstraction layer** with a **Certificate
Authority** built on top of it, containerized, deployed to Kubernetes, and
shipped by a pipeline whose security checks are gates rather than reports.
Private keys are generated on, and never leave, a hardware security module.

Written as a reference for one question that comes up in every HSM
integration and is usually answered badly: *how do you build on a hardware
security module without welding your codebase to one vendor's driver?*

---

## Why this is unusual

Most HSM integrations hard-code a single vendor. The PKCS#11 standard is
supposed to prevent that, and in practice does not — vendors disagree about
attribute defaults, session semantics, object search behaviour and error
codes, in ways that only surface against real hardware.

So the interesting claim is not "this code calls PKCS#11". It is that the
same interface drives **two independent backends** with no vendor-specific
branches in the calling code, and that this was proven by running a second,
real vendor against an interface designed before it arrived.

| Backend | Status |
|---|---|
| **SoftHSM2** | Runs in CI on every push. No hardware, no SDK, reproducible by anyone. |
| **Thales ProtectServer** | Runs locally against the maintainer's own token. |

Two, not five. A list of vendor names in a README costs nothing; an
abstraction implemented once is a guess, and this repository does not claim
support it has not run.

## The PKCS#11 core

`internal/pkcs11` is the centre of the project, not a detail of it.

- **One interface, one shared core.** Both adapters delegate to a common
  implementation (`base.go`). The interface needed *zero* vendor-specific
  overrides once the second, real vendor was run against it — which is the
  evidence that the abstraction generalizes rather than the assertion.
- **One conformance suite, run per backend.** Every test that touches a
  token runs as its own subtest against every backend the environment
  provides, so a pass or a skip is visible per vendor in the log. A backend
  the environment lacks skips; it never fails. Adding a vendor is a registry
  entry and an adapter, not an edit to every test file.
- **PINs live in C-heap memory.** A PIN in a Go `[]byte` can be copied by
  the garbage collector during a stack or heap move, leaving a copy nothing
  can overwrite. `SecurePIN` holds it in memory that does not move, so
  zeroization can guarantee the bytes it wrote over were the only ones.
- **A token is identified by its serial number, never its label.** PKCS#11
  defines `CKA_LABEL` as a description and never requires it to be unique,
  and permits slot IDs to change. Labels address; serials identify. A lookup
  that matches more than one token is ambiguous and fails closed rather than
  resolving to the first hit — because "the first hit" is a decision made by
  enumeration order, which is nobody's decision.

## The Certificate Authority

A two-tier hierarchy, where the separation is structural rather than
procedural.

- The **root** lives on its own token, is created by an offline,
  operator-driven ceremony, and signs exactly two things: the intermediate's
  certificate and the root CRL. The online service has no configuration
  field capable of naming the root's token — enforced by a test, so it
  cannot regress into a warning.
- The **intermediate** signs end-entity certificates and the leaf CRL. The
  service refuses to start if handed a self-signed certificate, so a
  misconfiguration that would put a root online is rejected rather than
  logged.
- **Revocation is decided before the signature.** A certificate's CRL
  distribution point and AIA pointer are fixed the moment it is signed, so
  the CA refuses to issue at all when it has nowhere to publish revocation.
  A certificate issued without a distribution point can never gain one.
- **Its own authority is checked at the point of use.** Before signing, the
  CA verifies that its issuing certificate asserts the key usage the
  operation needs, is inside its own validity window, and can cover the
  lifetime about to be granted. Startup validation does not discharge this:
  a process correctly configured an hour ago is still running after its
  issuer expired.

## The signing layer

The PKCS#11 core is the platform's single signing foundation, not just the
CA's key store. Certificates, container images and release artifacts are
each signed by a **separate** HSM-held key over the same custody boundary.

Purpose separation is about blast radius: a compromised image-signing key
must not be able to issue a certificate, and a compromised CA key must not
be able to sign a release. Every key carries a **versioned label**
(`image-signing-key-v1`), and verifiers consume a published, signed **key
inventory** rather than a hard-coded key — so rotation means provisioning
the next version, keeping the previous one verify-only for a stated window,
then destroying it on the token. Overwriting a label in place would make
rotation a breaking change, which in practice means it never happens.

The Kubernetes admission policy is **generated from that inventory**, never
hand-written, and the generator verifies the inventory's signature before
rendering it. Images are admitted by digest, never by tag: a signature is
over a digest, and a tag is a pointer that can be repointed after admission
has already approved it.

## The pipeline

Six checks, and they are not six opinions about one thing. Each reads a
different artifact, and a finding from one is invisible to the others:

| Check | Reads | Answers |
|---|---|---|
| Suite + coverage floor | the code, against SoftHSM2 | does it work against a real token? |
| Semgrep | the code you wrote | did we introduce a defect? |
| gitleaks | every commit in history | did we commit a secret, ever? |
| `trivy fs` + `govulncheck` | what you imported | is a vulnerable version present — and do we reach it? |
| `trivy image` | what was assembled | is the shipped image vulnerable? |
| `trivy config` + OpenTofu | what would be provisioned | is the infrastructure misconfigured? |

Every check is a script in `ci/`, run the same way locally and in the
pipeline, so a red check is reproducible without pushing again. All six are
**required** on `main`, including for the repository owner — a gate the
owner can wave through is a report, not a gate.

That is demonstrated rather than asserted:
**[PR #4](https://github.com/LockedWayi/multivendor-hsm-pki/pull/4)**
deliberately swaps `crypto/rand` for `math/rand` in the request-id
generator, with the reasoning someone would genuinely have. Semgrep turns
red, the merge is refused (`the base branch policy prohibits the merge`),
and a second commit on the same branch turns it green. The detail worth
reading is which checks *passed*: build, vet, tests and coverage were all
green throughout. The test suite cannot see that defect, which is the
entire argument for having a scanner as well as tests. Accepted
findings live in **one** reviewed allowlist and must carry a written reason
and an expiry date — an exception nobody has to renew is a forgotten risk,
not an accepted one.

## What is verified, and how

This project makes claims automation cannot check, so the two are labelled
separately and never averaged:

- **CI-verified.** Build, vet, race-detector suite and coverage floor
  against SoftHSM2; SAST; full-history secret scan; dependency, reachability
  and image scanning; infrastructure scanning. Reproducible by anyone with
  Docker and no hardware.
- **Maintainer-verified.** Everything involving the Thales ProtectServer
  token: the conformance suite against a second real vendor, CA issuance and
  revocation end to end, and durable-key signing. Run on the maintainer's own
  hardware and reported as such.

A release that blurs those two is the version of this repository that
damages its own credibility, so it does not.

## Running it

Everything runs in a container; no HSM required.

```sh
# Build the dev environment (Go + a real SoftHSM2 module)
docker build -f ci/softhsm2-dev.Dockerfile -t hsm-pki-dev .

# The full suite against a real PKCS#11 token
docker run --rm -v "$PWD:/repo" -w /repo hsm-pki-dev go test -race -p 1 ./...

# The gates the pipeline runs
ci/scan-code.sh          # Semgrep
ci/scan-deps.sh          # trivy fs + govulncheck
ci/terraform-scan.sh     # OpenTofu fmt, validate, trivy
```

`deploy/docker/run-local.sh` brings up the service against a throwaway
SoftHSM2 token, and `CONTRIBUTING.md` has the rest.

## Verifying a release

A release artifact's signature is checked by a program that holds only the
public key and shares no code with the signer:

```sh
go run ./ci/verify-artifact \
    -key docs/keys/artifact-signing-key-v1.pub \
    -bundle release/hsm-pki-server.bundle \
    release/hsm-pki-server
```

It exits zero only when the bundle names that key, the digest it carries is
the digest of the bytes actually supplied, and the signature verifies over
them. Anything else — including a bundle it does not recognise — is
non-zero. A signature checked only by the tool that produced it proves that
the tool agrees with itself, which it would do just as convincingly if the
whole encoding were wrong.

## Security posture

- Private keys are generated on the HSM and never leave it. No private key
  is written to disk, returned by an API, or emitted to a log at any level.
  PINs follow the same rule and live in memory for the minimum window.
- No secrets in the repository or its history. `gitleaks` scans every commit
  on every push, with its exceptions committed and reviewed.
- The `ghp_…` token in the OpenTofu history is **deliberate, fake, and
  worthless**: a realistic-looking credential planted to demonstrate that
  the scanner catches one, removed in the following commit, and allowlisted
  by a single commit-pinned fingerprint rather than a rule or path
  exemption. It authenticates nothing.
- Cryptographic primitives come from the Go standard library
  (`crypto/x509`, `crypto/ecdsa`, `crypto/rand`) and PKCS#11 from the mature
  `miekg/pkcs11` binding. No hand-rolled crypto. P-256 by default.
- Every ambiguous security decision fails closed, and all enforcement is
  server-side; client-side checks exist for user experience only.

## Status

The PKCS#11 core, the CA and its two-tier hierarchy, the container and its
Kubernetes deployment with a generated admission policy, the
infrastructure-as-code modules, and the scanning pipeline are built and
running. Authentication on the write endpoints, the signing gate in its
fail-closed form, and Vault-based key custody are in progress.

Checks currently **report rather than block**: branch protection requires a
plan this repository is not on yet. The scripts themselves fail closed, and
a red check is treated as blocking by convention until the setting can make
it so.

## License

See [LICENSE](LICENSE).
