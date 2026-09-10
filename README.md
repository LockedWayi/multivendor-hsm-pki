# HSM-PKI Platform

![coverage](docs/coverage.svg)

A vendor-agnostic **PKCS#11 abstraction layer** with a **Certificate
Authority** built on it, containerized, deployed to Kubernetes, and shipped
by a pipeline whose security checks block merges. Private keys never leave
the HSM. The design reasoning is in
**[docs/architecture.md](docs/architecture.md)**.

## Why this is unusual

Most HSM integrations hard-code one vendor. This one drives two PKCS#11
implementations through one interface with no vendor-specific code.

| Backend | Status |
|---|---|
| **SoftHSM2** | Runs in CI on every push. No hardware, no SDK, reproducible by anyone. |
| **Thales ProtectServer** | Thales ProtectToolkit-C 7.3.3 software emulation (`libctsw.so`, token model `SW:SWEMUL`), on the maintainer's own installation. Not an appliance. |

Two spec-conformant implementations needed no vendor-specific code. That is
not proof the abstraction is complete. nShield and Luna are untested, and
differences are expected in the login and key protection model, `CKA_ID`
and label handling, EC point encoding, session limits and error codes.

- **One interface, one shared core.** Both adapters wrap a common
  implementation (`base.go`) with no overrides.
- **One conformance suite, run per backend.** Every test that touches a
  token runs as its own subtest against every backend the environment
  provides. A backend the environment lacks skips. Adding a vendor is a
  registry entry and an adapter.
- **PINs live in C-heap memory.** `SecurePIN` holds the PIN in memory the
  Go garbage collector does not move or copy. One copy is outside this
  code: [docs/threat-model.md](docs/threat-model.md) §6.3.
- **A token is identified by its serial number, never its label.** PKCS#11
  defines `CKA_LABEL` as a description and permits slot IDs to change. A
  lookup that matches more than one token fails closed.

## The Certificate Authority

- The **root** lives on its own token, created by an offline ceremony. It
  signs the intermediate's certificate and the root CRL. The online service
  has no configuration field that can name the root's token. A test
  enforces that.
- The **intermediate** signs end-entity certificates and the leaf CRL. The
  service refuses to start if handed a self-signed certificate.
- **Revocation is decided before the signature.** A certificate's CRL
  distribution point and AIA pointer are fixed when it is signed. The CA
  refuses to issue when it has nowhere to publish revocation.
- **Its own authority is checked at the point of use.** Before signing, the
  CA verifies that its issuing certificate asserts the key usage the
  operation needs, is inside its validity window, and covers the lifetime
  about to be granted.

## The signing layer

Certificates, container images and release artifacts are each signed by a
**separate** HSM-held key over the same custody boundary. A compromised
image-signing key cannot issue a certificate. A compromised CA key cannot
sign a release. Every key carries a **versioned label**
(`image-signing-key-v1`), and verifiers consume a published, signed **key
inventory**. Rotation provisions the next version, keeps the previous one
verify-only for a stated window, then destroys it on the token.

The Kubernetes admission policy is **generated from that inventory**, and
the generator verifies the inventory's signature first. Images are admitted
by digest.

## The pipeline

Eight checks. Each reads a different artifact, and a finding from one is
invisible to the others:

| Check | Reads | Answers | Required |
|---|---|---|---|
| Suite + coverage floor | the code, against SoftHSM2 | does it work against a real token? | yes |
| Semgrep | the code you wrote | did we introduce a defect? | yes |
| gitleaks | every commit in history | did we commit a secret, ever? | yes |
| `trivy fs` + `govulncheck` | what you imported | is a vulnerable version present, and do we reach it? | yes |
| `trivy image` | what was assembled | is the shipped image vulnerable? | yes |
| `trivy config` + OpenTofu | what would be provisioned | is the infrastructure misconfigured? | yes |
| trust chain | the key inventory, against an anchor in another repository | can this tree still say which key is which? | yes |
| run verification | the keyless signature, both attestations and the binary bundle this run made | are they checkable from a clean checkout, for this run's exact identity? | after merge |

Every check is a script in `ci/`, run the same way locally and in the
pipeline. Seven of the eight are **required** on `main`, the repository
owner included, and `enforce_admins` is on. No pull-request review is
required. See A10 in the threat model.

The eighth, run verification, checks the signatures on an image that has
already been published, which only happens on a merge to `main`. It is
skipped on pull requests, runs after the merge, and a failure turns `main`
red. `ci/verify-release.sh` and admission refuse a wrongly signed image.

**[PR #4](https://github.com/LockedWayi/multivendor-hsm-pki/pull/4)** shows a
gate blocking. It swaps `crypto/rand` for `math/rand` in the request-id
generator. Semgrep turns red, the merge is refused (`the base branch policy
prohibits the merge`), and a second commit turns it green. Tests were green
throughout. Accepted findings live in **one** reviewed allowlist and must
carry a written reason and an expiry date.

## The published image, and how to verify it

A push to `main` that clears every gate publishes the service image to
`ghcr.io/lockedwayi/multivendor-hsm-pki`, signed keyless, with a CycloneDX
SBOM attestation and a SLSA provenance attestation. The bytes are pushed
under the moving tag `staging`, the digest is signed, and only then are
`sha-<commit>` and, on a release tag, `v<x.y.z>` applied. `staging` names
the most recent build pushed, signed or not. Nothing should pull it. There
is no `latest`. **The digest is the identity.**

### Verifying a release

```sh
HSM_PKI_TRUST_ANCHOR_REPO=... HSM_PKI_TRUST_ANCHOR_COMMIT=... HSM_PKI_TRUST_ANCHOR_SHA256=... \
    ci/verify-release.sh ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:<digest>
```

Three files that agree in one repository prove nothing. The chain starts
with inputs the verifier supplies:

| # | Link | Why it is where it is |
|---|---|---|
| 1 | **anchor** | fetched from the anchor repository at the commit and with the SHA-256 the verifier supplies in `HSM_PKI_TRUST_ANCHOR_REPO`, `_COMMIT` and `_SHA256`. Nothing in this tree names them. An unreachable or mismatched anchor refuses. There is no fallback to the copy in this tree. |
| 2 | **inventory** | `docs/keys/key-inventory.json` verified against that anchor **by openssl**, an implementation that did not produce the signature. |
| 3 | **the key** | read out of the verified inventory, never hardcoded. A signature from a previous key version keeps verifying while that version is listed `verify-only`. |
| 4 | **the image** | verified by digest, with no token mounted anywhere. |

Changing the anchor file in place needs write access to
`LockedWayi/hsm-pki-trust-anchor`, where force-pushes are refused. A consumer
who copies the three values from this README trusts this repository for
that step. That is the residual. The values today are:

```
HSM_PKI_TRUST_ANCHOR_REPO=LockedWayi/hsm-pki-trust-anchor
HSM_PKI_TRUST_ANCHOR_COMMIT=13a8d605df7379f247ab3643b769552a206c6d22
HSM_PKI_TRUST_ANCHOR_SHA256=afc3febd028c566b30a04e2dfd38f4a8740ca2dada5bdb12e2eb5e701913d888
```

By hand, it is four commands:

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

The pipeline extracts the server binary from the image it just signed and
signs it keyless. On a `v<x.y.z>` tag the binary, its Sigstore bundle and
its SHA-256 are attached to a GitHub Release after a separate job has
verified them.

```sh
gh release download v<x.y.z> --repo LockedWayi/multivendor-hsm-pki \
    --pattern 'hsm-pki-server*'
sha256sum --check hsm-pki-server.sha256
cosign verify-blob --bundle hsm-pki-server.sigstore.json \
    --certificate-identity 'https://github.com/LockedWayi/multivendor-hsm-pki/.github/workflows/ci.yml@refs/tags/v<x.y.z>' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    hsm-pki-server
```

No release exists yet. Each run on `main` keeps those three files as the
`release-binary-<sha>` workflow artifact for 90 days.

### The two signatures

Every digest carries the pipeline's keyless signature: a short-lived Fulcio
certificate for the workflow run's GitHub OIDC identity, recorded in Rekor.
The two attestations are made the same way, and a consumer can check them
from a machine holding no file from this repository:

```sh
cosign verify \
    --certificate-identity 'https://github.com/LockedWayi/multivendor-hsm-pki/.github/workflows/ci.yml@refs/heads/main' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:<digest>
cosign verify-attestation --type cyclonedx       <same identity flags> <same ref>
cosign verify-attestation --type slsaprovenance1 <same identity flags> <same ref>
```

For a release tag the identity ends in `@refs/tags/v<x.y.z>`. That identity
is not in the key inventory, so admission ignores the keyless signature.

The **durable path** is what releases use. The maintainer counter-signs a
release digest with `image-signing-key-v1` on their own token and re-attests
the SBOM and the provenance with the same key
(`ci/countersign-release.sh <digest>`). That key is listed in the inventory,
the inventory is signed by an offline token, and the anchor lives in another
repository. Admission accepts only this signature, and CI cannot make it.

One digest carries it today. Check it with the anchor inputs above:

```sh
HSM_PKI_TRUST_ANCHOR_REPO=... HSM_PKI_TRUST_ANCHOR_COMMIT=... HSM_PKI_TRUST_ANCHOR_SHA256=... \
    ci/verify-release.sh ghcr.io/lockedwayi/multivendor-hsm-pki@sha256:0848e76a2236b177b890efb9c7e41050904622a9edc075c7dee18fee58266e0a
```

## Status

- **CI-verified.** Build, vet, race suite and coverage floor against
  SoftHSM2; SAST; full-history secret scan; dependency, reachability and
  image scanning; infrastructure scanning. Reproducible with Docker.
- **Maintainer-verified.** Everything involving the ProtectServer backend,
  run against Thales ProtectToolkit-C 7.3.3 software emulation.

Built and running: the PKCS#11 core, the two-tier CA, the container and its
Kubernetes deployment with a generated admission policy, the
infrastructure-as-code modules, the scanning pipeline, and the signing
layer. In progress: authentication on the write endpoints (mTLS, issued by
this platform's own CA), the key-rotation drill in CI, and Vault custody.

## Running it

Everything runs in a container. No HSM is required.

```sh
docker build -f ci/softhsm2-dev.Dockerfile -t hsm-pki-dev .            # Go + SoftHSM2
docker run --rm -v "$PWD:/repo" -w /repo hsm-pki-dev go test -race -p 1 ./...
ci/scan-code.sh          # Semgrep
ci/scan-deps.sh          # trivy fs + govulncheck
ci/terraform-scan.sh     # OpenTofu fmt, validate, trivy
```

[CONTRIBUTING.md](CONTRIBUTING.md) has the rest.

## Security posture

- No private key is written to disk, returned by an API, or emitted to a
  log at any level. PINs follow the same rule.
- No secrets in the repository or its history. `gitleaks` scans every commit
  on every push. The `ghp_…` token in the OpenTofu history is **fake**,
  planted to show the scanner catches one, and allowlisted by one
  commit-pinned fingerprint.
- Cryptographic primitives come from the Go standard library and PKCS#11
  from the `miekg/pkcs11` binding. P-256 by default.
- Every ambiguous security decision fails closed. All enforcement is
  server-side.

## License

See [LICENSE](LICENSE).
