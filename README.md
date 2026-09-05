# HSM-PKI Platform

A vendor-agnostic **PKCS#11 abstraction layer** over three HSM families (nShield,
Luna, ProtectServer), with a **Certificate Authority** built on top, deployed to
Kubernetes (a security-gated **CI/CD pipeline** lands in Phase 5), and — at the
capstone — with its root of trust anchored to a real HSM via **Vault auto-unseal**.

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
the capstone auto-unseal mechanism included, once it lands — runs in CI with no
HSM and no proprietary SDK (`.github/workflows/ci.yml`: the race-detector
suite, the coverage floor, Semgrep, a full-history secret scan, dependency
and reachability scanning, an image scan with an SBOM, and infrastructure
scanning — all on every PR).
Clone it, run `go test ./...` in the provided dev container, and everything CI
checks runs on your machine too.

Those checks currently **report rather than block**. Marking them *required*
needs branch protection, which GitHub does not offer on a private repository
on the free plan — so a red run here is loud, and advisory. Saying so is
cheaper than the alternative: a reader who assumes a gate exists and finds
out otherwise has learned something worse than the gap itself.

The whole platform runs the same way, not just its tests:

```sh
deploy/docker/run-local.sh
```

That initializes two SoftHSM2 tokens, runs the real offline root ceremony
against them, moves the root's token out of the store the service can reach,
and starts the containerized CA read-only and non-root. Then:

```sh
curl -s localhost:8080/readyz
curl -s localhost:8080/root.crl | openssl crl -inform DER -noout -text
curl -X POST --data-binary @your.csr localhost:8080/certificates
```

No PKCS#11 module ships inside the service image — every module is mounted at
run time, so the image contains no key store and the same image runs against
SoftHSM2 and a vendor HSM with only configuration changing. That decision and
what it costs are in [`deploy/docker/README.md`](deploy/docker/README.md).

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
- No secrets in the repo or its history — `gitleaks` scans the full history
  on every PR and push (advisory today, see above).
- Dependencies are scanned two ways, because they answer different
  questions: `trivy fs` for *is a vulnerable version present*, `govulncheck`
  for *does this code actually reach it*. The image is scanned too, and an
  accepted finding needs a written reason and an expiry date in one reviewed
  allowlist — `ci/vuln-allowlist.yaml`, empty today.
- Standard-library crypto; `miekg/pkcs11` for PKCS#11 — no hand-rolled crypto.
- ECDSA P-256 default curve.
- Fail-closed on every ambiguous security decision; all enforcement server-side.
- Signing is purpose-separated at the key level, and on separate *tokens*:
  the CA hierarchy's keys (offline root, online intermediate — Phase 3b),
  `image-signing-key` and `artifact-signing-key` on a supply-chain token of
  their own, and `inventory-signing-key` offline again. They are distinct
  HSM-held keys behind the same PKCS#11 core, never interchangeable — a
  compromised image key cannot issue a certificate, and a compromised CA key
  cannot sign a release. Separate tokens rather than separate labels because
  PKCS#11 authenticates a *token*, not a key.
- Keys carry versioned labels and a **published, signed inventory** —
  [`docs/keys/`](docs/keys/) — so rotation is a lifecycle event rather than
  a breaking change: a new version arrives `active`, the previous one goes
  `verify-only` for a stated window, and only then is it destroyed on the
  token. Verifiers read the inventory, never a hard-coded key. Anyone can
  check it with nothing but `openssl`:

  ```sh
  openssl dgst -sha256 -verify docs/keys/inventory-signing-key-v1.pub \
      -signature docs/keys/key-inventory.json.sig docs/keys/key-inventory.json
  ```

  See `docs/architecture.md`, "The signing layer."

## Status

Phase 1 (PKCS#11 core), Phase 2 (CA core), Phase 3 (infrastructure as
code) and Phase 3b (PKI hardening) complete. **Phase 4 (containerization
and Kubernetes) is in progress**: the image, its Kubernetes deployment, the
scanning gate and the purpose-separated signing keys are built; the
admission-policy and image-signing halves remain.

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

Every issued leaf in turn carries its own CRL distribution point
(`<ca.base_url>/crl`) and AIA CA-Issuers pointer
(`<ca.base_url>/intermediate.crt`), both served by this service as DER under
the RFC 2585 media types a relying party following those URLs expects, and
the CA
refuses to issue at all if it has nowhere to publish revocation — an
extension is fixed by its signature, so a certificate issued without a
distribution point can never gain one. No OCSP URL is written anywhere until
the responder exists in Phase 5b: pointing a verifier at a responder that
will not answer is worse than pointing it at nothing.

Verified against both SoftHSM2 and the maintainer's ProtectServer token in a
single `go test -race -p 1 ./...` run. (`-p 1` matters: the package test
binaries `go test` would otherwise run in parallel all open the same
emulator token store — see `docs/protectserver-setup.md` §5.)

Revocation state and the CRL number counter live in an embedded SQLite store
behind an interface, so a restart no longer resurrects a revoked
certificate — proven by a regression test that issues, revokes, tears the
server down, brings it back over the same file, and re-fetches the CRL.

Phase 3b is now complete — code and documents both.

Phase 4 (in progress): a multi-stage build producing a **53.8 MB
`distroless/cc` image** with no shell, no package manager and no PKCS#11
module of any kind — every module, SoftHSM2 included, is a read-only mount,
so the CI backend and the vendor backend are delivered by the same code and
differ only in configuration. It runs `--read-only --user 65532 --cap-drop
ALL`, and on K3s (via k3d) as a single replica with `Recreate`, a
`restricted` Pod Security Admission namespace, probes wired to
`/healthz`/`/readyz`, and the CA store on a `PersistentVolume` — verified by
issuing a certificate through the Service and by destroying and rebuilding
the cluster to confirm a revocation survives it. `trivy` reports zero
HIGH/CRITICAL across 11 OS packages and the gate is proven to fail on a
deliberately outdated image.

Phase 4 also builds the **signing layer**: `image-signing-key-v1` and
`artifact-signing-key-v1` on a supply-chain token of their own, and
`inventory-signing-key-v1` on an offline token that holds none of the keys
it vouches for — four tokens in total, because PKCS#11 authenticates a
*token*, not a key. What is published is not a bare PEM but a **signed key
inventory** ([`docs/keys/`](docs/keys/)) that any verifier can check with
nothing but `openssl`, and a mechanical audit (`internal/keyaudit`) fails
the test suite if any configuration file names a CA key and a signing key
together. Provisioning it needs no hardware:
[`deploy/docker/provision-signing-keys.sh`](deploy/docker/provision-signing-keys.sh).

The release binary is signed over the HSM with that artifact key, through
cosign, with **no transparency log**: the signing config declares no log
service, because Rekor exists to bound the lifetime of an ephemeral
certificate and this platform signs with a long-lived published key, so an
entry would put a record of every internal release in a public log without
changing the trust decision. Verification does not need cosign, an HSM, or
a PIN — `ci/verify-artifact` re-derives the answer from `crypto/ecdsa` and
`crypto/sha256`, and refuses a bundle whose digest is not the digest of the
bytes in front of it:

```sh
go run ./ci/verify-artifact -key docs/keys/artifact-signing-key-v1.pub \
    -bundle hsm-pki-server.bundle hsm-pki-server
```

That second verifier is not belt and braces. A signature checked only by the
tool that produced it proves the tool agrees with itself — the closed loop
that shipped a CRL here that Go could read and OpenSSL could not
([`docs/lessons.md`](docs/lessons.md) §2).

Still open in Phase 4, and stated rather than implied: the Kyverno
admission policy, and container-image signing with admission verification.

The security reasoning behind all of this — what each key is worth, what an
attacker gets by compromising the service process and what they still do not
get, and the seven things this platform deliberately does not defend
against — is in [`docs/threat-model.md`](docs/threat-model.md). The root
ceremony as an operator procedure, the manifest it produces, disaster
recovery per tier, and the wrap-based backup design are in
[`docs/key-ceremony-and-recovery.md`](docs/key-ceremony-and-recovery.md).

Per-sub-task detail is tracked in
[`docs/phases/phase-1-pkcs11-core.md`](docs/phases/phase-1-pkcs11-core.md),
[`docs/phases/phase-2-ca-core.md`](docs/phases/phase-2-ca-core.md),
[`docs/phases/phase-3-infrastructure.md`](docs/phases/phase-3-infrastructure.md),
[`docs/phases/phase-3b-pki-hardening.md`](docs/phases/phase-3b-pki-hardening.md),
and [`docs/phases/phase-4-container-k8s.md`](docs/phases/phase-4-container-k8s.md).

## License

Apache-2.0 — chosen over MIT for its explicit patent grant, the conventional
choice for security/cryptography tooling where patent clarity matters. See
[`LICENSE`](LICENSE).
