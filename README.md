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
> nShield softcards, Luna partitions, and ProtectServer slots — with the CA above
> it never learning which vendor holds its keys.

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full design and the
reasoning behind each decision. The system is built in seven layered phases, each
proven before the next is added:

1. **Multi-vendor PKCS#11 core** — one Go interface, SoftHSM2-backed, no hardware
   needed to run.
2. **CA core** — issue / revoke / CRL, HSM-agnostic by construction.
3. **Infrastructure as code** — Terraform modules, scanned with `tfsec`.
4. **Container + Kubernetes** — distroless image, hardened pods, admission policy.
5. **CI/CD security gates** — SAST, dependency/image/secret scanning, auto-deploy.
6. **Vault integration** — key custody moves out of the service.
7. **HSM-backed Vault auto-unseal** — root of trust anchored to hardware (capstone).

Phase specs live in [`docs/phases/`](docs/phases/).

## Runs without hardware

The entire platform develops and tests against **SoftHSM2**, so the full suite —
including the capstone auto-unseal mechanism — runs in CI with no HSM. The
vendor-specific and real-hardware paths are documented and clearly labelled as
the parts that need hardware, so the rest stays reproducible by anyone.

## Security posture

- Private keys and PINs never touch plaintext disk or logs.
- No secrets in the repo or its history (`gitleaks`-enforced).
- Standard-library crypto; `miekg/pkcs11` for PKCS#11 — no hand-rolled crypto.
- ECDSA P-256 default curve.
- Fail-closed on every ambiguous security decision; all enforcement server-side.

## Status

Scaffolding complete. Phase 1 (PKCS#11 core) in progress.

## License

Apache-2.0 — chosen over MIT for its explicit patent grant, the conventional
choice for security/cryptography tooling where patent clarity matters. See
[`LICENSE`](LICENSE).
