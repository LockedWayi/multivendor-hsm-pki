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
reasoning behind each decision. The system is built in seven layered phases, each
proven before the next is added:

1. **Multi-vendor PKCS#11 core** — one Go interface, proven against two
   independent backends: SoftHSM2 (no hardware needed) and Thales ProtectServer.
2. **CA core** — issue / revoke / CRL, HSM-agnostic by construction.
3. **Infrastructure as code** — Terraform modules, scanned with `tfsec`.
4. **Container + Kubernetes** — distroless image, hardened pods, admission policy.
5. **CI/CD security gates** — SAST, dependency/image/secret scanning, auto-deploy.
6. **Vault integration** — key custody moves out of the service.
7. **HSM-backed Vault auto-unseal** — root of trust anchored to hardware (capstone).

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

## Status

Phase 1 (PKCS#11 core) and Phase 2 (CA core) complete.

Phase 1: the interface, session lifecycle, PIN custody, and both the
SoftHSM2 and ProtectServer adapters are implemented, tested, and share one
extracted core (`internal/pkcs11/base.go`) — proof that the interface
needed zero vendor-specific overrides once a second, real vendor was run
against it. A single conformance suite (`TestConformance`) runs against
both backends.

Phase 2: an HSM-backed `crypto.Signer`, CA bootstrap and issuance with CSR
validation, and a full HTTP surface — `POST /certificates`,
`POST /certificates/{serial}/revoke`, `GET /crl`, `GET /healthz`/`GET /readyz`
— all signing through the Phase 1 adapter, never holding a raw key.
Verified against a real, running server with `openssl`-generated CSRs and
`openssl verify`/`openssl crl -verify`, on both SoftHSM2 and the
maintainer's ProtectServer token.

Per-sub-task detail is tracked in
[`docs/phases/phase-1-pkcs11-core.md`](docs/phases/phase-1-pkcs11-core.md) and
[`docs/phases/phase-2-ca-core.md`](docs/phases/phase-2-ca-core.md).

## License

Apache-2.0 — chosen over MIT for its explicit patent grant, the conventional
choice for security/cryptography tooling where patent clarity matters. See
[`LICENSE`](LICENSE).
