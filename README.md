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

The design reasoning — why one interface over three vendors, why the keys
are purpose-separated, why the hierarchy is two-tier, and what was rejected
along the way — is in **[docs/architecture.md](docs/architecture.md)**.

## Why this is unusual

Most HSM integrations hard-code one vendor. PKCS#11 is meant to prevent
that, and in practice vendors differ in attribute defaults, session
semantics, object search behaviour and error codes. Those differences
only show against a second implementation.

One interface drives two backends with no vendor-specific code in the
shared implementation.

| Backend | Status |
|---|---|
| **SoftHSM2** | Runs in CI on every push. No hardware, no SDK, reproducible by anyone. |
| **Thales ProtectServer** | Thales ProtectToolkit-C 7.3.3 software emulation (`libctsw.so`, token model `SW:SWEMUL`), on the maintainer's own installation. Not an appliance. |

Two spec-conformant implementations needed no vendor-specific code. That
is not proof that the abstraction is complete. nShield and Luna are
untested, and that is where differences are expected: the login and key
protection model, `CKA_ID` and label handling, EC point encoding, session
limits, error codes.

## The PKCS#11 core

`internal/pkcs11` is the centre of the project, not a detail of it.

- **One interface, one shared core.** Both adapters wrap a common
  implementation (`base.go`) with no overrides. Two conformant
  implementations agreeing is evidence, not proof; see above.
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

Eight checks, and they are not eight opinions about one thing. Each reads a
different artifact, and a finding from one is invisible to the others:

| Check | Reads | Answers | Required |
|---|---|---|---|
| Suite + coverage floor | the code, against SoftHSM2 | does it work against a real token? | yes |
| Semgrep | the code you wrote | did we introduce a defect? | yes |
| gitleaks | every commit in history | did we commit a secret, ever? | yes |
| `trivy fs` + `govulncheck` | what you imported | is a vulnerable version present — and do we reach it? | yes |
| `trivy image` | what was assembled | is the shipped image vulnerable? | yes |
| `trivy config` + OpenTofu | what would be provisioned | is the infrastructure misconfigured? | yes |
| trust chain | the key inventory, against an anchor in another repository | can this tree still say which key is which? | yes |
| run verification | the keyless signature, both attestations and the binary bundle this run made | are they checkable from a clean checkout, for this run's exact identity? | after merge |

Every check is a script in `ci/`, run the same way locally and in the
pipeline, so a red check is reproducible without pushing again.

Seven of the eight are **required** on `main`, including for the repository
owner — a gate the owner can wave through is a report, not a gate.
`enforce_admins` is on, force-pushes and deletions are refused.

The eighth is the honest row, and it is not an oversight. Run verification
checks the signatures on an image that has *already been published*, which
only happens on a merge to `main` — so there is nothing for it to verify
while a pull request is open, and it is skipped there. Marking it required
would block every merge on a check that never reports. It runs after the
merge instead, and a failure turns `main` red.

That is a real gap and it is left visible rather than closed by wording: a
signature defect is caught minutes after landing, not before. What prevents
it reaching a consumer is downstream — an unsigned or wrongly signed image
is refused by `ci/verify-release.sh` and by admission.

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

## The published image, and how to verify it

A push to `main` that clears every gate publishes the service image to
`ghcr.io/lockedwayi/multivendor-hsm-pki`, signed keyless with a CycloneDX
SBOM attestation and a SLSA provenance attestation. The bytes are pushed under the
moving tag `staging`, the digest is signed, and only then are
`sha-<commit>` and, when the commit carries a release tag, `v<x.y.z>`
applied. A successful push therefore leaves `staging`, `sha-<commit>` and
possibly `v<x.y.z>`. `staging` always names the most recent build pushed,
signed or not, and nothing should pull it. There is no `latest` and no
moving `main`. **The digest is the identity.** Pull the digest form.

### Verifying a release

```sh
HSM_PKI_TRUST_ANCHOR_REPO=... HSM_PKI_TRUST_ANCHOR_COMMIT=... HSM_PKI_TRUST_ANCHOR_SHA256=... \
    ci/verify-release.sh ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:<digest>
```

An inventory, its signature and the key that verifies it, all in one
repository, only show that the three files agree. Whoever can write to the
repository can change all three in one commit. So the chain starts with
inputs the verifier supplies:

| # | Link | Why it is where it is |
|---|---|---|
| 1 | **anchor** | fetched from the anchor repository at the commit and with the SHA-256 the verifier supplies in `HSM_PKI_TRUST_ANCHOR_REPO`, `_COMMIT` and `_SHA256`. Nothing in this tree names them. An unreachable or mismatched anchor refuses; there is no fallback to the copy in this tree. |
| 2 | **inventory** | `docs/keys/key-inventory.json` verified against that anchor **by openssl** — an implementation that is not this project's code and did not produce the signature. |
| 3 | **the key** | read *out of* the verified inventory, never hardcoded. This is what makes rotation work: a signature from a previous key version keeps verifying while that version is listed `verify-only`. |
| 4 | **the image** | verified by digest, with no token mounted anywhere. |

What that buys, stated narrowly. Changing the anchor file in place needs
write access to `LockedWayi/hsm-pki-trust-anchor`, where force-pushes and
deletions are refused. Replacing the anchor needs the consumer to accept
new anchor inputs. A consumer who copies the three values from this README
trusts this repository for that step; that is the residual. The values
today are:

```
HSM_PKI_TRUST_ANCHOR_REPO=LockedWayi/hsm-pki-trust-anchor
HSM_PKI_TRUST_ANCHOR_COMMIT=13a8d605df7379f247ab3643b769552a206c6d22
HSM_PKI_TRUST_ANCHOR_SHA256=afc3febd028c566b30a04e2dfd38f4a8740ca2dada5bdb12e2eb5e701913d888
```

You can also do it by hand; it is four commands and worth reading once:

```sh
curl -fsSL "https://raw.githubusercontent.com/$HSM_PKI_TRUST_ANCHOR_REPO/$HSM_PKI_TRUST_ANCHOR_COMMIT/inventory-signing-key-v1.pub" -o anchor.pub
sha256sum anchor.pub                       # must equal HSM_PKI_TRUST_ANCHOR_SHA256
openssl dgst -sha256 -verify anchor.pub \
    -signature docs/keys/key-inventory.json.sig docs/keys/key-inventory.json
cosign verify --key <the image key listed in that inventory> \
    --insecure-ignore-tlog=true ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:<digest>
cosign verify-attestation --key <same key> --type cyclonedx       --insecure-ignore-tlog=true <same ref>
cosign verify-attestation --key <same key> --type slsaprovenance1 --insecure-ignore-tlog=true <same ref>
```

### The release binary

The pipeline extracts the server binary from the image it just signed, so
both signatures cover the same bytes, and signs the binary keyless. On a
`v<x.y.z>` tag the binary, its Sigstore bundle and its SHA-256 are attached
to a GitHub Release, after a separate job has verified them.

```sh
gh release download v<x.y.z> --repo LockedWayi/multivendor-hsm-pki \
    --pattern 'hsm-pki-server*'
sha256sum --check hsm-pki-server.sha256
cosign verify-blob --bundle hsm-pki-server.sigstore.json \
    --certificate-identity 'https://github.com/LockedWayi/multivendor-hsm-pki/.github/workflows/ci.yml@refs/tags/v<x.y.z>' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    hsm-pki-server
```

No release exists yet. Until one does, each run on `main` keeps the same
three files as the `release-binary-<sha>` workflow artifact for 90 days.

### The two signatures, and which one you can verify today

**No published image has been counter-signed yet.** Every digest on GHCR
carries one signature, and every digest published from now on carries the
pipeline's keyless signature: cosign obtains a short-lived certificate
from Fulcio for the workflow run's GitHub OIDC identity and records the
signature in Rekor. The CycloneDX SBOM attestation and the SLSA v1
provenance attestation are made the same way, on every build of `main`.
That is what a consumer can verify today, from a machine holding no file
from this repository:

```sh
cosign verify \
    --certificate-identity 'https://github.com/LockedWayi/multivendor-hsm-pki/.github/workflows/ci.yml@refs/heads/main' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:<digest>
cosign verify-attestation --type cyclonedx       <same identity flags> <same ref>
cosign verify-attestation --type slsaprovenance1 <same identity flags> <same ref>
```

For a release tag the identity ends in `@refs/tags/v<x.y.z>`. The keyless
signature says: this workflow, at this ref, built this digest, and Rekor
recorded it at that time. It is not in the key inventory, so admission
ignores it and `ci/verify-release.sh` does not accept it.

The **durable path** is what releases use. The maintainer counter-signs a
release digest with `image-signing-key-v1` on their own token and
re-attests the SBOM and the provenance with the same key
(`ci/countersign-release.sh <digest>`). That key is listed in the
inventory, the inventory is signed by an offline token, and the anchor for
that signature lives in another repository. Admission accepts only this
signature. `ci/verify-release.sh` requires the signature and both
attestations by a key from the inventory. No digest has this yet.

CI does not hold the durable key. Holding it would mean committing key
material or exposing the maintainer's machine to pipeline execution.

## What is verified, and how

This project makes claims automation cannot check, so the two are labelled
separately and never averaged:

- **CI-verified.** Build, vet, race-detector suite and coverage floor
  against SoftHSM2; SAST; full-history secret scan; dependency, reachability
  and image scanning; infrastructure scanning. Reproducible by anyone with
  Docker and no hardware.
- **Maintainer-verified.** Everything involving the ProtectServer backend:
  the conformance suite, CA issuance and revocation end to end, and
  durable-key signing. Run against Thales ProtectToolkit-C 7.3.3 software
  emulation on the maintainer's own installation, and reported as such.

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
infrastructure-as-code modules, the scanning pipeline, and the signing
layer are built and running: every build of `main` is signed keyless with
SBOM and SLSA provenance attestations, the PKCS#11 signing path is proved
on every publish against a throwaway registry, and a release verifier
checks the durable signature against an anchor outside this tree.

In progress: authentication on the write endpoints (mTLS, using this
platform's own CA to issue the client certificates), the key-rotation drill
in CI, and Vault-based key custody.

Seven of the eight checks are required on `main`, `enforce_admins`
included: suite, SAST, secret scan, dependency scan, image scan,
infrastructure scan and trust chain. Counted from the branch-protection
API on 2026-09-09. The eighth, run verification, runs only after a publish
and cannot gate a merge; see "The pipeline" above.

## License

See [LICENSE](LICENSE).
