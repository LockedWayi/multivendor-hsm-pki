# HSM-PKI Platform

A vendor-agnostic **PKCS#11 abstraction layer** over three HSM families (nShield,
Luna, ProtectServer), with a **Certificate Authority** built on top, deployed to
Kubernetes through a **security-gated CI/CD pipeline**, and — at the capstone —
with its root of trust anchored to a real HSM via **Vault auto-unseal**.

Built as a public reference for how a cryptography/PKI engineer abstracts multiple
HSM vendors cleanly and roots software key management in hardware trust, end to
end.

> **Why this is unusual:** most HSM integrations hard-code a single vendor. The
> core of this project is one Go interface that presents the same shape over
> each vendor's isolated key space — a ProtectServer slot, an nShield softcard,
> a Luna partition — with the CA above it never learning which vendor holds its
> keys. Today that interface is proven against two independent backends,
> SoftHSM2 and ProtectServer; nShield and Luna are Phase 7 and are stated as
> gaps until they are real.

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full design and the
reasoning behind each decision. The system is built in layered phases, each
proven before the next is added:

- **Phase 1 — Multi-vendor PKCS#11 core**: one Go interface, proven against two
  independent backends: SoftHSM2 (no hardware needed) and Thales ProtectServer.
- **Phase 2 — CA core**: issue / revoke / CRL, HSM-agnostic by construction.
- **Phase 3 — Infrastructure as code**: OpenTofu modules, scanned with `trivy`.
- **Phase 3b — PKI hardening**: two-tier hierarchy (offline root, online
  intermediate), persistent revocation state, CDP/AIA, threat model and
  key-ceremony/recovery docs.
- **Phase 4 — Container + Kubernetes**: distroless image, hardened pods,
  admission policy, purpose-separated signing keys.
- **Phase 5 — CI/CD security gates**: SAST, dependency/image/secret scanning,
  HSM-backed signing and SLSA provenance as blocking gates, auto-deploy.
- **Phase 5b — Issuance policy & OCSP**: certificate profiles, naming
  authorization, delegated OCSP responder.
- **Phase 6 — Vault integration**: key custody moves out of the service.
- **Phase 7 — HSM-backed Vault auto-unseal**: root of trust anchored to
  hardware (capstone).
- **Phase 8 — Verifiable evidence** (post-capstone): signed, hash-chained
  audit log; crypto-agility/PQC-readiness design.

Phase specs live in [`docs/phases/`](docs/phases/).

## Runs without hardware

The baseline path develops and tests against **SoftHSM2**, so the full suite —
including the capstone auto-unseal mechanism — runs in CI with no HSM and no
proprietary SDK. Clone it, run `go test ./...` in the provided dev container,
and everything CI checks runs on your machine too.

A second adapter targets **Thales ProtectServer** through the ProtectToolkit
PKCS#11 module. It is optional, and it is the part you cannot reproduce without
your own Thales entitlement — the SDK is proprietary and is never vendored
here, so this path runs locally and never in CI. See
[`docs/protectserver-setup.md`](docs/protectserver-setup.md).

The split is deliberate and is kept visible rather than blurred: SoftHSM2 gives
reproducibility, ProtectServer gives the evidence that one interface really does
survive a second, independent vendor. Phase acceptance criteria state which
claims an automated run backs and which rest on the maintainer's own
verification.

## Security posture

- Private keys and PINs never touch plaintext disk or logs.
- No secrets in the repo or its history (`gitleaks`-enforced).
- Standard-library crypto; `miekg/pkcs11` for PKCS#11 — no hand-rolled crypto.
- ECDSA P-256 default curve.
- Fail-closed on every ambiguous security decision; all enforcement server-side.
- Signing is purpose-separated at the key level: the CA hierarchy's keys
  (offline root, online intermediate — Phase 3b), `image-signing-key`, and
  `artifact-signing-key` are distinct HSM-held keys behind the same PKCS#11
  core, never interchangeable — a compromised image key cannot issue a
  certificate, and a compromised CA key cannot sign a release. Keys carry
  versioned labels and a published, signed inventory so rotation is a
  lifecycle event, not a breaking change. See `docs/architecture.md`,
  "The signing layer."

## Status

Phase 1 (PKCS#11 core), Phase 2 (CA core), and Phase 3 (infrastructure as
code) complete. **Phase 3b (PKI hardening) is in progress**: the two-tier
hierarchy and durable revocation state are built; certificate profile
extensions and two design documents remain.

Phase 1: the interface, session lifecycle, PIN custody, and both the
SoftHSM2 and ProtectServer adapters are implemented, tested, and share one
extracted core (`internal/pkcs11/base.go`) — proof that the interface
needed zero vendor-specific overrides once a second, real vendor was run
against it. A single conformance suite (`TestConformance`) runs against
both backends.

Phase 2: an HSM-backed `crypto.Signer`, CA issuance with CSR
validation, and a full HTTP surface — `POST /certificates`,
`POST /certificates/{serial}/revoke`, `GET /crl`, `GET /healthz`/`GET /readyz`
— all signing through the Phase 1 adapter, never holding a raw key.
Verified against a real, running server with `openssl`-generated CSRs and
`openssl verify`/`openssl crl -verify`, on both SoftHSM2 and the
maintainer's ProtectServer token.

Phase 3: OpenTofu modules for the maintainer's Hostinger VPS (imported,
never created, guarded by `lifecycle { prevent_destroy = true }`),
`dev`/`staging` environments composed from the same modules, a
locked-and-encrypted remote state backend on self-hosted MinIO, and
`trivy`-based policy/secret scanning with a demonstrated real catch. See
[`deploy/terraform/README.md`](deploy/terraform/README.md).

Phase 3b (in progress): a two-tier CA. `cmd/hsm-pki-keytool ceremony` runs
a one-time, operator-driven ceremony that generates the root and
intermediate key pairs on **two separate tokens**, self-signs the root
(`pathlen:1`), signs the intermediate under it (`pathlen:0`), and emits the
root CRL — three public artifacts and no private key material. The service
then loads that intermediate and refuses to start on a self-signed
certificate, so a configuration that would put a root online is rejected
rather than warned about. Issuance returns the leaf plus the intermediate;
the root certificate and CRL are served as static artifacts at `/root.crt`
and `/root.crl`, which is where the intermediate's AIA and CDP point.

Verified against both SoftHSM2 and the maintainer's ProtectServer token in a
single `go test -race ./...` run.

Revocation state and the CRL number counter live in an embedded SQLite store
behind an interface, so a restart no longer resurrects a revoked
certificate — proven by a regression test that issues, revokes, tears the
server down, brings it back over the same file, and re-fetches the CRL.

**Still open in Phase 3b**, and load-bearing enough to name here rather than
bury: issued leaf certificates do not yet carry CDP/AIA extensions (sub-task
3b.4 — the ceremony-time half is done). The threat model and
key-ceremony/recovery documents are not written (3b.5, 3b.6).

Per-sub-task detail is tracked in
[`docs/phases/phase-1-pkcs11-core.md`](docs/phases/phase-1-pkcs11-core.md),
[`docs/phases/phase-2-ca-core.md`](docs/phases/phase-2-ca-core.md),
[`docs/phases/phase-3-infrastructure.md`](docs/phases/phase-3-infrastructure.md),
and [`docs/phases/phase-3b-pki-hardening.md`](docs/phases/phase-3b-pki-hardening.md).

## License

Apache-2.0 — chosen over MIT for its explicit patent grant, the conventional
choice for security/cryptography tooling where patent clarity matters. See
[`LICENSE`](LICENSE).
