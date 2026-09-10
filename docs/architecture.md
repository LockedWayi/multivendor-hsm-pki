# Architecture

This document explains the shape of the system and the reasoning behind
the major choices. It answers "why is it built this way".

---

## What this is, in one paragraph

A vendor-agnostic PKCS#11 abstraction layer sits at the core. It presents
one interface over several HSM families: SoftHSM2 and ProtectServer today,
nShield and Luna planned. A Certificate Authority is built on that core.
It issues, revokes and reports X.509 certificates without caring which
vendor's HSM holds its keys. The service is containerized, deployed to
Kubernetes, and shipped by a CI/CD pipeline that scans code, dependencies
and images before anything ships. The planned capstone anchors the CA's
root of trust to a hardware HSM through HashiCorp Vault auto-unseal. The
same core is the platform's signing foundation beyond certificates.
Container images and release artifacts are signed by their own HSM-held
keys over the same PKCS#11 boundary.

## What this is not

This is a reference implementation and a portfolio piece. It is not a
commercial product. It contains no tenant-rental logic, no licensing or
metering, and no region-specific compliance framing.

---

## The core idea: one interface, many vendors

Every HSM vendor speaks PKCS#11. Each has its own quirks, its own
management tooling, and its own notion of an isolated key space. nShield
calls it a softcard, Luna a partition, ProtectServer a slot. Most
integrations target one vendor and hard-code its assumptions.

The core of this project is a single Go interface that hides those
differences.

```
              CA / applications
                     │
        one PKCS#11-shaped interface        ← VendorAdapter
    ┌─────────┬──────┴───────┬─────────┐
 SoftHSM2  ProtectServer  nShield    Luna   ← vendor implementations
  token       slot        softcard  partition ← each vendor's isolated key space
 ✅ built     ✅ built     ○ planned ○ planned
 (CI runs)  (local only)
```

Two of those four run. **SoftHSM2** is the baseline. It needs no hardware
and no proprietary SDK, so CI runs it and any reader can reproduce the
whole suite. **ProtectServer** runs through Thales ProtectToolkit-C 7.3.3
software emulation, on the maintainer's own installation. nShield and Luna
are planned and untested.

Both adapters wrap the shared implementation with no overrides. Two
spec-conformant implementations needing no vendor-specific code is
evidence that the interface is usable across vendors. It is not proof that
the abstraction is complete. nShield and Luna are where differences are
expected: the login and key protection model, `CKA_ID` and label handling,
EC point encoding, session limits, and error codes.

### ProtectToolkit-C software emulation, as measured

Thales ProtectToolkit-C 7.3.3, `libctsw.so`, token model `SW:SWEMUL`, on
the maintainer's own installation. It is an emulator, not an appliance.
The module loads with no `LD_LIBRARY_PATH` and links only against libdl,
libpthread and libc. Slot 1 holds the admin token. Slot 0 is the user
token the operator initializes.

One difference from SoftHSM2 in what the conformance suite exercises:
`C_Verify` rejects a signature over an all-zero digest with
`CKR_SIGNATURE_INVALID`. SoftHSM2 accepts it. An all-zero digest does not
occur with real messages, so no workaround exists and the suite uses real
digests only. Everything else behaves as on SoftHSM2: sessions, `C_Login`
as `CKU_USER`, `C_GenerateRandom`, EC P-256 key pairs, AES keys,
`CKM_ECDSA` sign and verify with a 64-byte `r||s` signature,
`CKM_AES_CBC_PAD`, `CKM_AES_KEY_WRAP`, object search and attribute reads.
`CKA_EC_POINT` is returned DER-wrapped (`0x04 0x41 || point`), as on
SoftHSM2. The behaviours that differ outside the conformance suite are in
[`test-matrix.md`](test-matrix.md), "Expected divergences to look for".

---

## The layering, and why it is ordered this way

Each layer is proven before the next is added, so the security-critical
surface is never large and untested at once.

1. **PKCS#11 abstraction and vendor adapters (Go).** The core. One
   interface, run against two backends: SoftHSM2 in CI, and ProtectServer
   through ProtectToolkit-C software emulation, run locally. If this layer
   is wrong, nothing on top matters.

2. **CA core (Go).** Certificate issue, revoke and CRL, built on the
   abstraction so it is HSM-agnostic from the start. Standard-library
   crypto only.

3. **Infrastructure as code (OpenTofu).** Somewhere to run, defined as code
   so it is reproducible and scannable. You cannot scan infrastructure you
   built by hand.

   PKI hardening lands before anything is containerized. The CA becomes a
   two-tier hierarchy (offline root, online intermediate) and revocation
   state becomes durable. These change what the service is, so they land
   beneath the container, Kubernetes and CI layers.

4. **Containerization and Kubernetes (Docker, K3s).** The service becomes
   a portable, immutable, scanned artifact with an orchestrator. K3s for
   the local environment. Manifests are written to standard Kubernetes APIs
   so they run unchanged on managed cloud.

5. **CI/CD with security gates.** Every push is scanned for insecure code
   (SAST), vulnerable dependencies and images, and leaked secrets before
   deploy.

   Planned next: authentication on the issuance API, then an enforced
   issuance policy (certificate profiles, naming authorization) and a
   delegated OCSP responder. Those controls separate a CA from a signing
   oracle.

6. **Vault with HSM auto-unseal (planned capstone).** Key custody moves
   out of process memory into Vault, and Vault's own root of trust is
   anchored to a hardware HSM.

7. **Verifiable evidence (planned).** A signed, hash-chained audit log of
   everything the CA did, countersigned by its own purpose-separated HSM
   key, plus a crypto-agility and PQC-readiness design. The capstone
   proves the keys were held right. This proves what was done with them
   can be audited after the fact.

---

## The signing layer: one core, four purposes

The PKCS#11 core exists to hold private keys and use them without handing
them out. A Certificate Authority is the obvious consumer of that
property. A container image and a release binary need the same thing: a
signature only the holder of a key inside the HSM could have produced,
over content anyone can check without holding anything secret.

This platform treats signing as one capability with several consumers.
Three of them sign something for somebody else to check:

```
┌── offline token ──┐   ┌── online token ──┐   ┌─ supply-chain token ────┐
│ ca-root-key-v1    │   │ ca-intermediate  │   │ image-signing-key-v1    │
│                   │   │ -key-v1          │   │ artifact-signing-key-v1 │
└────────┬──────────┘   └────────┬─────────┘   └───┬──────────────┬──────┘
         │                       │                 │              │
  cmd/hsm-pki-keytool     internal/pkcs11    cosign sign    cosign sign-blob
  ceremony, run once      core + internal/ca (--key         (--key
  by an operator          in the daemon      "pkcs11:...")  "pkcs11:...")
         │                       │                 │              │
  root certificate        X.509 leaf certs,  OCI image      release-artifact
  (pathlen:1),            leaf CRL           signature      signature bundle
  intermediate cert              │                 │              │
  (pathlen:0),            verified by        verified at    verified in CI
  root CRL                relying parties    admission      before packaging;
         │                via the chain      (Kyverno);     a bad signature
  served as static                           an unsigned    stops the build
  artifacts by the                           image is
  service                                    rejected
```

The fourth key signs nothing a consumer sees. It signs the list of the
other three, and it lives on a token of its own:

```
┌─ offline inventory token ─┐
│ inventory-signing-key-v1  │
└─────────────┬─────────────┘
              │  cmd/hsm-pki-keytool generate-inventory
              ▼
      docs/keys/key-inventory.json  +  .json.sig
              │
              │  names image-signing-key-v1 and artifact-signing-key-v1,
              │  each with a purpose, a public key and a lifecycle state
              ▼
   every verifier: cosign invocations, the Kyverno policy,
   the CI trust-chain job, a README's verification recipe
```

Why a token of its own rather than the root's: the root's token is opened
for a ceremony and nothing else. Putting the anchor there would make every
supply-chain rotation a root-token access, with witnesses and a procedure,
and a control that expensive gets skipped. Keeping them apart also keeps
`signingkey.CheckNoCAHierarchyKey` absolute, with no exception for this
one key.

The boundary on the left is the one that matters most. The root's token is
never named by the running service's configuration, so the daemon never
authenticates it. Everything to the right of it is reachable by a
compromised process. The root is not.

There are four tokens here, and the third and fourth exist for the reason
in [`threat-model.md`](threat-model.md) §6.1. PKCS#11 authenticates a
token, not a key. Any process holding a session on a token can find every
key on it by label and sign with it. Distinct labels separate purposes
against mistakes. They do nothing against an attacker who has the session.
The CA daemon holds an anchor login on the online token for its whole
lifetime. Putting the image and artifact keys there would have meant a
compromise of the CA process yielding image and release signing too.

The supply-chain keys are therefore provisioned on their own token. The
boundary that matters is drawn twice: the root is unreachable from the
online service because the service cannot name its token, and the signing
keys are unreachable from the CA daemon for the same reason. Moving them
further, onto a token only a release process can reach, is a deployment
change rather than a re-provisioning.

Separate keys per purpose. A signing key is a liability as much as an
asset: whatever it can sign, an attacker who reaches it can sign too. One
key for everything means one compromise forges certificates, images and
releases.

Two refinements sharpen this picture:

- **The CA is two keys across two tokens.** An offline root signs only the
  intermediate's certificate and the root CRL, in a ceremony. An online
  intermediate does the daily issuing. The service's configuration has no
  field capable of naming the root's token or key, so compromising the
  process yields at worst a revocable intermediate. The two tokens are
  checked to be distinct by their PKCS#11 serial numbers and by confirming
  the intermediate's key is not visible from the root's token. A serial is
  a claim. An object search is a measurement.
- **Every signing key lives under a versioned label and a published,
  signed key inventory**, so rotation is a lifecycle state change verifiers
  already understand. The planned audit chain adds a fourth purpose,
  `audit-signing-key`, under the same rules.

The CA issuing a certificate to one of the other keys is not key reuse.
That is the CA doing its ordinary job, binding an identity to a public
key.

### The key inventory: what a verifier is allowed to trust

A signing key is only useful to someone who can decide, later and without
the HSM, whether a signature came from a key that was allowed to make it.
Publishing one PEM per purpose answers that until the first rotation. At
that point every consumer has to change on the same day: cosign
invocations, admission policies, the verification recipe in a README. A
rotation that expensive does not happen, and the key outlives the reason
anyone trusted it.

What gets published is an **inventory**, and verifiers consume the
inventory rather than a key. The document as a whole records:

| Field | Why it is there |
|---|---|
| `schema` | Inside the signed bytes, so a future format change cannot be presented as this one. |
| `version` | Monotonic, so a rollback is detectable. An old list naming a retired key cannot be presented as current without the number saying so. The policy generator enforces it: it refuses an inventory whose version is lower than the one its existing rendering was produced from. |
| `generated_at` / `valid_until` | Bounds how long a stale document stays acceptable. Without an expiry, an attacker who can withhold updates replays yesterday's list forever and a retired key never dies. TUF calls this a freeze attack. Every verifier in this repository refuses an inventory past `valid_until`. |

And per key version:

| Field | Why it is there |
|---|---|
| `label` | The versioned CKA_LABEL (`image-signing-key-v1`). What an operator types and what a PKCS#11 URI carries. Addressing, not identity. |
| `purpose` | `image` or `artifact`. A verifier checking an image signature must be able to reject a signature made by the artifact key, or the separation is nominal. |
| `public_key` | PKIX PEM. The identity. Two labels naming one key pair is the reuse the purpose rule forbids, and only this field can see it. |
| `curve` | P-256 today. Stated so a future addition is a data change rather than an assumption. |
| `valid_from` / `retired_at` | Bounds what a signature's date can be checked against. |
| `status` | `active`, `verify-only`, or `retired`. |

The three states are the lifecycle. Rotation provisions `-v(N+1)` as
`active`, marks `-vN` `verify-only` for a stated window, and only then
retires it by destroying it on the token. A `verify-only` key signs
nothing new, and signatures it already made still verify. A verifier that
can hold exactly one key cannot express that window. The day the new key
appears is the day everything signed by the old one becomes unverifiable.
For images still running in a cluster, that is a live failure.

The inventory is itself signed. An unsigned list of trusted keys lets
anyone who can edit it add their own. It is signed by
`inventory-signing-key-v1`, on an offline token that holds none of the
keys it vouches for. That is the invariant behind TUF's offline root role,
Sigstore's own trust root and any offline X.509 root. An anchor stored
beside what it authorises authorises whoever holds the token.

It is generated by `hsm-pki-keytool generate-inventory` from the keys on
the token and never hand-edited. A hand-maintained inventory drifts from
the token, and the drift is undetectable when it matters. Live entries are
read back through `signingkey.Verify`, so a key the token reports as
extractable never reaches the published list. Retired entries come from
the previous document, because a retired key has been destroyed, and the
command refuses to call a key retired while its private half is still on
the token.

The signature covers the document's **exact bytes** rather than a
canonical re-encoding this repository computes, so checking it needs
nothing from here:

```sh
openssl dgst -sha256 -verify docs/keys/inventory-signing-key-v1.pub \
    -signature docs/keys/key-inventory.json.sig docs/keys/key-inventory.json
```

A signature only the library that produced it can check proves the code
agrees with itself. The published document, its signature and the three
public keys live in [`docs/keys/`](keys/).

**What speaks to the HSM.** The CA path goes through this repository's
own `VendorAdapter`. cosign does not. It links its own PKCS#11 binding and
opens the token itself, so what the two paths share is the token and the
standard interface, not this repository's Go code. What this repository
owns for the signing keys is their provisioning and custody policy,
generated through the PKCS#11 core by `cmd/hsm-pki-keytool`,
non-extractable, sensitive, one purpose each, plus the verification story
built around them. cosign runs on the same standard the abstraction
implements, against the same token.

Two signature paths exist. Every build of `main` is signed keyless by the
pipeline: a Fulcio certificate for the workflow's GitHub OIDC identity,
recorded in Rekor. The PKCS#11 path is proved on every publish against a
throwaway SoftHSM2 token and a throwaway registry, and nothing it signs is
published. The durable signature, with `image-signing-key-v1` on the
maintainer's token, is added to release digests by hand. It covers the
image, the SBOM attestation and the provenance attestation.

---

## Key design decisions

### One abstraction over several vendors, via PKCS#11
Rejected: vendor-specific SDKs and JCE providers (nShield's JCE, Luna's
Java provider). Chosen: PKCS#11 as the common denominator via
`miekg/pkcs11`. Reason: JCE and vendor SDKs are vendor-locked. PKCS#11 is
the shared standard every HSM implements.

### SoftHSM2 as the development and CI target
Rejected: developing against a vendor module. Chosen: SoftHSM2 first, and
the maintainer's own ProtectToolkit-C software emulation for validation of
the vendor path. Reason: it keeps development hardware-free, so CI can run
the whole suite, and it keeps this work independent of any employer's HSM.

### Why both SoftHSM2 and ProtectServer, rather than either alone
Rejected: SoftHSM2 only. An abstraction implemented once is a guess. Its
shape is free to encode one implementation's assumptions, and nothing
would catch that. Rejected too: ProtectServer only. It would make the
repository unreproducible for anyone without a Thales entitlement.

Chosen: both, behind one interface. SoftHSM2 carries CI and
reproducibility. ProtectToolkit-C software emulation is the second
implementation. Both adapters wrap the shared implementation with no
overrides. Two spec-conformant implementations needing no vendor-specific
code is evidence that the interface is usable across vendors. It is not
proof that the abstraction is complete. nShield and Luna are untested, and
that is where differences are expected: the login and key protection
model, `CKA_ID` and label handling, EC point encoding, session limits,
error codes.

The cost: the ProtectServer path cannot run in public CI, because the SDK
is proprietary and is never vendored here. Acceptance criteria are split
into CI-verifiable and maintainer-verified halves, so a reader can tell
which claims an automated run backs.

### Standard-library crypto only
Rejected: third-party crypto convenience libraries. Chosen: `crypto/x509`,
`crypto/ecdsa`, `crypto/rand`. Reason: importing an unaudited crypto
helper into a security reference undercuts it.

### ECDSA P-256 as the default curve, P-384 available
Rejected: RSA-2048 (larger, slower). Chosen: P-256 as the default. It is
the modern baseline, widely compatible, with a 128-bit symmetric-equivalent
security margin. P-384 (192-bit symmetric equivalent) is an explicit,
callable option for a root CA or a subject that warrants the larger margin
and can absorb the extra signing and verification cost. A CA should not
silently vary its own curve choice per certificate.

### One repository for the code, and two more beside it
Chosen: the code lives in one repository, with strict directory isolation
so the core could be extracted as a standalone library later.

Two later requirements added two repositories:

| Repository | Holds | Why it is separate |
|---|---|---|
| this one | all code, CI, deployment | the only place the gates run |
| `hsm-pki-trust-anchor` | one public key | an anchor stored beside what it authenticates authenticates nothing. Verification has to start outside the tree being verified |
| a private planning repo | plans, the engineering contract, vendor notes | working material a reader does not need, and some of it is not the maintainer's to publish |

The second is the one that matters architecturally. It is the difference
between a signature chain that survives a compromise of this repository
and one that does not.

### Fail-closed, enforcement server-side
Every ambiguous security decision rejects rather than degrades, and every
client-side component is untrusted. Reason: a CA that issues a
slightly-wrong certificate is worse than one that refuses and says why.
Any client can be decompiled, so trusting it is a design error.

### Purpose-separated signing keys rather than one platform key
Rejected: a single HSM-held key signing certificates, images, and
artifacts. It is simpler: one label to configure, one public key to
distribute. Chosen: three keys, one purpose each. Reason: blast-radius
isolation. The simpler design forces every consumer of a signature to
trust the union of every role that key plays, and makes any single
compromise total. The cost, three provisioning steps and three public keys
to publish, is paid once.

### Two-tier hierarchy rather than a single online CA
Rejected: one `ca-root-key` that both self-signs the root certificate and
signs every leaf, inside a network-facing daemon whose token stays
authenticated for the process lifetime. It is the simplest CA and the
right first shape to build. As an end state it violates this repository's
own blast-radius reasoning: compromise the service process and you hold
the root, and a root cannot be revoked, only replaced by rebuilding the
entire PKI. Chosen: root offline behind a ceremony, `pathlen:1`; online
intermediate with `pathlen:0` doing all issuance; the service configured
so it cannot name the root. Compromise of the online tier becomes "revoke
the intermediate and re-issue", an incident rather than an extinction
event. The cost is a ceremony step and a two-certificate chain for relying
parties, paid everywhere PKI runs. The ceremony as an operator runs it, the
manifest it produces, and the recovery path for each tier are in
[`key-ceremony-and-recovery.md`](key-ceremony-and-recovery.md).

### Durable revocation state rather than an in-memory registry
Rejected: an in-memory registry of issued and revoked certificates. A
process restart silently erases revocations, and a certificate revoked for
incident response reappears as valid. Chosen: a small embedded store
behind an interface, holding issued and revoked records and the CRL number
counter, with a restart regression test.

### Keys with lifecycles rather than immortal labels
Rejected: provisioning signing keys under bare labels
(`image-signing-key`) with a single published PEM per key. It works until
the first rotation, when every consumer must change at once, so the
rotation never happens. Chosen: versioned labels plus a signed key
inventory that verifiers consume, giving each key an explicit active,
verify-only, retired lifecycle. A rotation drill in CI is planned, not
built. The CA hierarchy's own rotation, intermediate re-issue as the
routine case and root roll-over with cross-signing as the exceptional one,
is in [`key-ceremony-and-recovery.md`](key-ceremony-and-recovery.md).

### No PKCS#11 module inside the service image
Rejected: installing SoftHSM2 into the image and mounting only the
proprietary vendor modules over it. That is what the licensing constraint
alone would suggest. SoftHSM2 is BSD-2-Clause and redistributable,
ProtectToolkit is not, and it keeps `docker run` self-contained. Chosen:
**no module of any kind ships in the image**. Every module, SoftHSM2
included, is mounted read-only at run time. Reason: the rejected shape
delivers the backend CI exercises differently from the backend production
uses. A difference between backends is where this repository has already
been bitten: the `CKA_SENSITIVE` defect existed for the life of the
project because one backend could not see it. Building the same asymmetry
into the packaging would repeat that. Two things fall out of it: the
published artifact contains no key store, and adding a vendor is a mount
plus a config value rather than a Dockerfile change.

The runtime base is sized for what gets mounted into the image. A mounted
module is `dlopen`ed into the service's own address space, so
`libsofthsm2.so` being C++ forces `distroless/cc`, which carries
`libstdc++`, where the service's own cgo binary would run on
`distroless/base`. The cost is that the image cannot start alone, which
moves the burden of zero-hardware reproducibility onto
`deploy/docker/run-local.sh`.

### cosign rather than a first-party signing tool
Rejected: a bespoke CLI over the core's `crypto.Signer`. It would
demonstrate the core more directly and would keep the PIN inside
`SecurePIN`. It would also mean inventing a signature envelope. Go's
standard library has no CMS/PKCS#7, and importing an unaudited third-party
one is forbidden here. A format nobody else can verify is a private
checksum. Rejected too: signing cosign's payload ourselves and using
`cosign attach signature`. That keeps the standard artifact layout but
hand-builds the payload, which is all of the divergence risk for none of
the simplicity.

Chosen: cosign for images and artifacts, with the keys provisioned and
governed through the core, plus an independent `crypto/ecdsa` cross-check
in Go that verifies the signature bytes rather than trusting the tool. The
cost is that PKCS#11 support lives behind cosign's `pkcs11key` build tag,
so the pipeline must use the `pivkey-pkcs11key` release build, and the PIN
passes through a process whose memory hygiene this repository does not
control. It is supplied by environment variable and never inside a PKCS#11
URI, where it would reach `ps` output, shell history, and CI logs.

### OpenTofu on Hostinger, an imported VPS, and plan-only staging
Chosen: OpenTofu manages the maintainer's existing Hostinger VPS via
`tofu import`, never `tofu apply` creating one. Not Terraform: HashiCorp's
BSL relicensing is worse licensing and governance for an open,
cleanly-provenanced piece than the Linux Foundation-governed fork.
Rejected: a fresh, disposable VPS, an added monthly cost for a
destroy-or-replace risk that a structural safeguard closes for free.
Chosen instead: `lifecycle { prevent_destroy = true }` on the imported
resource, turning any plan that would destroy or replace this
personally-used machine into a hard error. Rejected too: a second, real
VPS to prove `environments/staging` end to end. `tofu plan` already
proves the mechanism (identical modules, differing `.tfvars`), so staging
stays plan-only. State: self-hosted MinIO on the same VPS, locking via
OpenTofu's native S3 conditional-write lock, encryption via OpenTofu's
own client-side `encryption` block. A second commercial account
(Cloudflare R2) was rejected, and so was HashiCorp's Terraform Cloud:
routing state through HashiCorp's SaaS after leaving Terraform over its
licensing would be inconsistent. Full reasoning:
[`docs/terraform-state-backend-setup.md`](terraform-state-backend-setup.md).

---

## Scalability and production-readiness notes

- **Stateless service, external state.** Key material lives in the HSM.
  Issued and revoked records and the CRL number counter live in an
  embedded SQLite store behind the `internal/store.Store` interface, so a
  restart does not erase revocations. The store is single-writer at this
  scale. The connection pool is capped at one, which removes `SQLITE_BUSY`
  as a failure mode rather than managing it with retries. If replicas ever
  exist it moves to an external database, which is the swap the interface
  exists to permit. Adding connections here is not that swap. The
  in-memory implementation alongside it is for tests only, and nothing in
  `cmd/` constructs it.
- **Single instance until two things change.** The store is single-writer,
  and the generated CRL is cached per process, so a revocation on one
  instance would leave another serving a CRL that omits it until
  `nextUpdate`. Running more than one replica needs shared state and
  cross-instance cache invalidation. The manifest pins `replicas: 1` and
  says why.
- **Immutable artifacts.** The deployed unit is a scanned, versioned
  container image. Rollback is "deploy the previous image".
- **Everything reproducible from code.** Infrastructure, deployment, and
  pipeline are all code. The environment rebuilds from the repo.
- **Observability.** Structured logs (never containing secrets) and health
  and readiness endpoints are part of the service contract.
