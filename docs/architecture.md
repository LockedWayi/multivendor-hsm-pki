# Architecture

This document explains the *shape* of the system and the reasoning behind the
major choices. It answers "why is it built this way," which is the question the
intended reader — a security engineer evaluating this as a portfolio piece —
actually cares about. The phase files answer "what gets built when."

---

## What this is, in one paragraph

A vendor-agnostic PKCS#11 abstraction layer sits at the core, presenting one
interface over three different HSM families (SoftHSM, nShield, Luna, ProtectServer). A
Certificate Authority is built on that core: it issues, revokes, and reports
X.509 certificates without caring which vendor's HSM holds its keys. The whole
thing is containerized, deployed to Kubernetes, and shipped by a CI/CD pipeline
that scans code, dependencies, and images before anything ships. At the capstone,
the CA's root of trust is anchored to a real HSM through HashiCorp Vault
auto-unseal — software key management rooted in hardware trust. The same core
is also the platform's signing foundation beyond certificates: container images
and release artifacts are signed by their own HSM-held keys over the same
PKCS#11 boundary, and nothing unsigned reaches a cluster or a release.

## What this deliberately is *not*

This is a portfolio and reference implementation, not a commercial product. It
contains no tenant-rental logic, no licensing or metering, no region-specific
compliance framing. Those belong to a separate, private commercial effort. Here
they would only narrow the audience: an international reviewer cares whether the
author can abstract three HSM vendors cleanly and anchor a CA to hardware — not
about the business model of renting HSM capacity in one market.

---

## The core idea: one interface, many vendors

Every HSM vendor speaks PKCS#11, but each has its own quirks, its own management
tooling, and its own notion of an isolated key space (nShield calls it a softcard,
Luna a partition, ProtectServer a slot). Most engineers only ever integrate one
vendor and hard-code its assumptions.

The core of this project is a single Go interface that hides those differences.

Think of it like a power adapter for international travel. The appliance (the CA)
has one plug. The wall sockets (nShield, Luna, ProtectServer) are all shaped
differently. The adapter presents one plug to the appliance and knows how to fit
each socket. The appliance never learns there was a difference. That adapter is
the most valuable thing in this repository, because it is the part almost nobody
demonstrates across three vendors at once.

```
              CA / applications
                     │
        one PKCS#11-shaped interface        ← VendorAdapter
    ┌─────────┬──────┴───────┬─────────┐
 SoftHSM2  ProtectServer  nShield    Luna   ← vendor implementations
  token       slot        softcard  partition ← each vendor's isolated key space
 ✅ built     ✅ built     ○ Phase 7  ○ Phase 7
 (CI runs)  (local only)
```

Two of those four are the working proof. **SoftHSM2** is the universal
baseline: no hardware, no proprietary SDK, so CI runs it and any reader can
reproduce the whole suite. **ProtectServer** — via Thales ProtectToolkit — is a
real vendor implementation of the same interface. nShield and Luna are deferred
to Phase 7 and are honest gaps until then, not implied capabilities.

---

## The layering, and why it is ordered this way

Build order is deliberate: each layer is proven before the next is added, so the
security-critical surface is never large and untested at once. The analogy is
building a bank branch — you make sure the teller can count money by hand before
you install the vault door and connect it to the central reserve.

1. **PKCS#11 abstraction + vendor adapters (Go).** The core. One interface,
   proven against two independent backends — SoftHSM2 (needs no hardware, so CI
   runs it) and Thales ProtectServer (a real vendor module, run locally). If
   this layer is wrong, nothing on top matters.

2. **CA core (Go).** Certificate issue / revoke / CRL, built on the abstraction so
   it is HSM-agnostic from day one. Standard-library crypto only.

3. **Infrastructure as code (Terraform).** Somewhere to run, defined as code so it
   is reproducible and scannable. IaC from the start is what makes policy-as-code
   possible later — you cannot scan infrastructure you built by hand.

   *Then, before anything is containerized — PKI hardening (Phase 3b):* the
   CA becomes a real two-tier hierarchy (offline root, online intermediate)
   and revocation state becomes durable. Sequenced here deliberately: these
   change what the service *is*, so they must land beneath the container,
   Kubernetes, and CI layers rather than be retrofitted through them.

4. **Containerization + Kubernetes (Docker + K3s).** The service becomes a
   portable, immutable, scanned artifact with an orchestrator. K3s for the local
   environment; manifests written to standard Kubernetes APIs so they run
   unchanged on managed cloud.

5. **CI/CD with security gates.** The DevSecOps heart: every push is scanned for
   insecure code (SAST), vulnerable dependencies and images, and leaked secrets
   *before* deploy. "Shift left" — catch it where it is cheap.

   *Then — issuance policy & OCSP (Phase 5b):* with authentication in place,
   the CA gains an enforced issuance policy (certificate profiles, naming
   authorization) and a delegated OCSP responder — the controls that
   separate a CA from a signing oracle.

6. **Vault + HSM auto-unseal (capstone).** Key custody moves out of process memory
   into Vault, and Vault's own root of trust is anchored to a real HSM. This is
   the differentiator: few engineers can show software secrets management rooted
   in hardware, end to end.

7. **Verifiable evidence (Phase 8, post-capstone).** A signed, hash-chained
   audit log of everything the CA did, countersigned by its own
   purpose-separated HSM key, plus a crypto-agility/PQC-readiness design.
   The capstone proves the keys were held right; this proves what was done
   with them can be audited after the fact.

---

## The signing layer: one core, four purposes

The PKCS#11 core exists to hold private keys and use them without ever handing
them out. A Certificate Authority is the obvious consumer of that property —
but not the only one. A container image and a release binary need exactly the
same thing the CA does: a signature only the holder of a key inside the HSM
could have produced, over content anyone can then check without holding
anything secret.

So this platform treats signing as one capability with several consumers,
rather than as several unrelated features. Three of them sign something for
somebody else to check:

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
  root CRL                relying parties    admission      before packaging —
         │                via the chain      (Kyverno) —    a bad signature
  served as static                           an unsigned    stops the build
  artifacts by the                           image is
  service                                    rejected
```

The fourth key signs nothing a consumer sees. It signs the *list* of the
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
   every verifier: cosign invocations, the Kyverno policy (4.10),
   the CI verify job (5.9), a README's verification recipe
```

Why a token of its own rather than the root's: the root's token is opened
for a ceremony and nothing else, so putting the anchor there would make
every supply-chain rotation a root-token access — witnesses, a procedure,
and a control expensive enough that it gets skipped. Keeping them apart also
keeps `signingkey.CheckNoCAHierarchyKey` absolute, with no exception carved
out for this one key.

The dashed boundary on the left is the one that matters most: the root's
token is never named by the running service's configuration, so the daemon
never authenticates it. Everything to the right of it is reachable by a
compromised process; the root is not.

There are four tokens here, not two, and the third and fourth are there for
the same reason — [`threat-model.md`](threat-model.md) §6.1. PKCS#11 authenticates
a *token*, not a key: any process holding a session on a token can find
every key on it by label and sign with it. Distinct labels separate purposes
against mistakes; they do nothing against an attacker who has the session.
The CA daemon holds an anchor login on the online token for its whole
lifetime, so putting the image and artifact keys there would have meant a
compromise of the CA process yielding image and release signing too — §3.6's
guarantee true against slips and false against the adversary it names.

So the supply-chain keys were provisioned on their own token (decided in
Phase 4.8), and the boundary that matters is the same one drawn twice: the
root is unreachable from the online service because the service cannot name
its token, and the signing keys are unreachable from the CA daemon for
exactly the same reason. Moving them further — onto a token only CI can
reach — is a deployment change from here rather than a re-provisioning,
which is why this shape was chosen over the CI-controlled one before Phase 5
exists.

Separate keys per purpose, and the separation is the point. A signing key is
a liability as much as an asset: whatever it can sign, an attacker who
reaches it can sign too. One key for everything means one compromise forges
certificates *and* images *and* releases. The analogy is a company that keeps
its corporate seal, its shipping stamp, and its cheque signature as three
separate objects in three separate drawers — not because any one drawer is
insecure, but because losing one drawer should not lose the company.

Two refinements from the accepted 2026-08-26 architecture review sharpen
this picture:

- **The CA is two keys across two tokens**, built in Phase 3b: an offline
  root that only ever signs the intermediate's certificate and the root CRL
  in a ceremony, and an online intermediate that does the daily issuing.
  The service's configuration has no field capable of naming the root's
  token or key — compromising the process yields, at worst, a revocable
  intermediate. The two tokens are checked to be genuinely distinct by
  their PKCS#11 serial numbers *and* by confirming the intermediate's key
  is not visible from the root's token, because a serial is a claim and an
  object search is a measurement.
- **Every signing key lives under a versioned label and a published, signed
  key inventory** (CLAUDE.md §3.7), so rotation is a lifecycle state change
  verifiers already understand, not a breaking rename. Phase 8 adds a
  fourth purpose — `audit-signing-key`, countersigning the CA's
  tamper-evident audit log — under exactly the same rules.

The CA issuing a certificate *to* one of the other keys is not key reuse — that
is the CA doing its ordinary job, binding an identity to a public key, and it
is how a code-signing certificate is supposed to come into existence in the
first place.

### The key inventory: what a verifier is allowed to trust

A signing key is only useful to someone who can decide, later and without
the HSM, whether a signature came from a key that was allowed to make it.
Publishing one PEM per purpose answers that until the first rotation, at
which point every consumer — cosign invocations, admission policies, the
verification recipe in a README — has to change on the same day. In
practice that means the rotation never happens, which is how a key ends up
outliving the reason anyone trusted it.

So what gets published is an **inventory**, and verifiers consume the
inventory rather than a key. The document as a whole records:

| Field | Why it is there |
|---|---|
| `schema` | Inside the signed bytes, so a future format change cannot be presented as this one. |
| `version` | Monotonic, so a rollback is detectable: an old list naming a retired key cannot be presented as current without the number saying so. The policy generator enforces it: it refuses an inventory whose version is lower than the one its existing rendering was produced from. |
| `generated_at` / `valid_until` | Bounds how long a stale document stays acceptable. Without an expiry, an attacker who can *withhold* updates replays yesterday's list forever and a retired key never dies — TUF calls this a freeze attack. |

And per key version:

| Field | Why it is there |
|---|---|
| `label` | The versioned CKA_LABEL (`image-signing-key-v1`). What an operator types and what a PKCS#11 URI carries — addressing, not identity. |
| `purpose` | `image` or `artifact`. A verifier checking an image signature must be able to reject a signature made by the artifact key, or the separation is nominal. |
| `public_key` | PKIX PEM. The identity. Two labels naming one key pair is exactly the reuse §3.6 forbids, and only this field can see it. |
| `curve` | P-256 today; stated so a future addition is a data change rather than an assumption. |
| `valid_from` / `retired_at` | Bounds what a signature's date can be checked against. |
| `status` | `active`, `verify-only`, or `retired`. |

The three states are the lifecycle, and the middle one is why the inventory
exists at all. Rotation provisions `-v(N+1)` as `active`, marks `-vN`
`verify-only` for a stated window — it signs nothing new, but signatures it
already made still verify — and only then retires it by destroying it on the
token. A verifier that can hold exactly one key cannot express that window,
so the day the new key appears is the day everything signed by the old one
becomes unverifiable. For images that are still running in a cluster, that
is a live failure rather than a historical one.

The inventory is itself signed, because an unsigned list of trusted keys is
an invitation: anyone who can edit it can add their own. It is signed by
`inventory-signing-key-v1`, on an offline token that holds none of the keys
it vouches for — the invariant behind TUF's offline root role, Sigstore's
own trust root and any offline X.509 root. An anchor stored beside what it
authorises authorises whoever holds the token.

It is generated by `hsm-pki-keytool generate-inventory` from the keys
actually on the token and never hand-edited — a hand-maintained inventory
drifts from the token, and the drift is undetectable precisely when it
matters. Live entries are read back through `signingkey.Verify`, so a key
the token reports as extractable never reaches the published list; retired
entries come from the previous document, because a retired key has been
destroyed, and the command refuses to call a key retired while its private
half is still on the token.

The signature covers the document's **exact bytes** rather than a canonical
re-encoding this repository computes, so checking it needs nothing from
here:

```sh
openssl dgst -sha256 -verify docs/keys/inventory-signing-key-v1.pub \
    -signature docs/keys/key-inventory.json.sig docs/keys/key-inventory.json
```

That is CLAUDE.md §3.10 applied to this artifact: a signature only the
library that produced it can check proves the code agrees with itself, which
it would do just as convincingly if the format were wrong. The published
document, its signature and the three public keys live in
[`docs/keys/`](keys/).

**What actually speaks to the HSM, stated precisely.** The CA path goes through
this repository's own `VendorAdapter`. cosign does not: it links its own
PKCS#11 binding and opens the token itself, so what the two paths share is the
*token and the standard interface*, not this repository's Go code. What this
repository owns for the signing keys is their provisioning and custody policy —
generated through the Phase 1 core by `cmd/hsm-pki-keytool`, non-extractable,
sensitive, one purpose each — plus the verification story built around them.
Saying cosign "runs on our abstraction" would be the overclaim; it runs on the
same standard our abstraction implements, against the same token.

Two signature paths exist. Every build of `main` is signed keyless by the
pipeline: a Fulcio certificate for the workflow's GitHub OIDC identity,
recorded in Rekor. The PKCS#11 path is proved on every publish against a
throwaway SoftHSM2 token and a throwaway registry, and nothing it signs is
published. The durable signature, with `image-signing-key-v1` on the
maintainer's token, is added to release digests by hand. No published
digest carries it yet.

---

## Key design decisions

### One abstraction over three vendors, via PKCS#11
Rejected: vendor-specific SDKs / JCE providers (nShield's JCE, Luna's Java
provider). Chosen: PKCS#11 as the common denominator via `miekg/pkcs11`. Reason:
JCE and vendor SDKs are vendor-locked; PKCS#11 is the shared standard every HSM
implements. Abstracting at the PKCS#11 layer is what makes one interface over
three vendors possible at all.

### SoftHSM2 as the development and CI target
Rejected: developing against real hardware. Chosen: SoftHSM2 first, real hardware
only for final validation of vendor-specific paths. Reason: it keeps development
hardware-free (so CI can run the whole suite), and — critically — it keeps this
work cleanly independent of any employer's HSM, which matters for provenance.

### Why both SoftHSM2 and ProtectServer, rather than either alone
Rejected: SoftHSM2 only — an abstraction that has only ever been implemented
once is a guess, not an abstraction. Its shape is free to quietly encode one
reference implementation's assumptions, and nothing would catch that. Rejected
too: ProtectServer only — it would make the repository unreproducible for
anyone without a Thales entitlement, and a portfolio piece nobody can run is a
claim rather than a demonstration.

Chosen: both, behind one interface. SoftHSM2 carries CI and reproducibility;
ProtectServer carries the proof. The evidence is specifically that *one
interface satisfies both without changing* — that is what distinguishes a real
abstraction from a wrapper around a single vendor, and it is the single most
load-bearing claim in this repository.

The cost is accepted deliberately: the ProtectServer path cannot run in public
CI, because the SDK is proprietary and is never vendored here. Phase 1's
acceptance criteria are therefore split into CI-verifiable and
maintainer-verified halves, so a reader can tell which claims an automated run
backs. Blurring the two would be the dishonest version of this trade.

### Standard-library crypto only
Rejected: third-party crypto convenience libraries. Chosen: `crypto/x509`,
`crypto/ecdsa`, `crypto/rand`. Reason: for a piece whose whole point is security
credibility, importing an unaudited crypto helper undercuts the message.

### ECDSA P-256 as the default curve, P-384 available
Rejected: RSA-2048 (larger, slower). Chosen: P-256 as the out-of-the-box
default — the modern baseline, widely compatible, and adequate security
margin (128-bit symmetric equivalent) for the vast majority of certificates
this CA issues. P-384 (192-bit symmetric equivalent) is exposed as an
explicit, callable option — for a root CA or a subject that specifically
warrants the larger margin and can absorb the extra signing/verification
cost — rather than a second default; a CA should not silently vary its own
curve choice per certificate.

### One repository for the code, module-isolated — and two more beside it
Chosen: the code lives in one repository telling one story, with strict
directory isolation so the core could be extracted as a standalone library
later. Reason: for a portfolio, one coherent narrative beats scattered
repos, and the isolation preserves the "library-grade core" property.

That was originally a plain mono-repo decision, and it did not survive
contact with two later requirements, so the honest description is now three
repositories with sharply different jobs:

| Repository | Holds | Why it is separate |
|---|---|---|
| this one | all code, CI, deployment | the story, and the only place the gates run |
| `hsm-pki-trust-anchor` | one public key | an anchor stored beside what it authenticates authenticates nothing — verification has to start outside the tree being verified |
| a private planning repo | phase plans, the engineering contract, vendor notes | working material a reader does not need, and some of it is not the maintainer's to publish |

The second is the one that matters architecturally. It is not organisation:
it is the difference between a signature chain that survives a compromise of
this repository and one that does not.

### Fail-closed, enforcement server-side
Every ambiguous security decision rejects rather than degrades, and every
client-side component is untrusted. Reason: a CA that issues a slightly-wrong
certificate is worse than one that refuses and says why; and any client can be
decompiled, so trusting it is a design error.

### Purpose-separated signing keys rather than one platform key
Rejected: a single HSM-held key signing certificates, images, and artifacts —
operationally simpler, one label to configure, one public key to distribute.
Chosen: three keys, one purpose each (`CLAUDE.md` §3.6). Reason: blast-radius
isolation. The simpler design forces every consumer of a signature to trust the
union of every role that key plays, and makes any single compromise total. The
cost — three provisioning steps and three public keys to publish — is paid once,
at setup, and never again.

### Two-tier hierarchy rather than a single online CA
Rejected: the Phase 2 shape kept permanently — one `ca-root-key` that both
self-signs the root certificate and signs every leaf, inside a
network-facing daemon whose token stays authenticated for the process
lifetime (the anchor login). Simplest possible CA, and the right *first*
shape to build — but as an end state it is a blast-radius violation of this
repository's own signing-layer reasoning: compromise the service process
and you hold the root, and a root cannot be revoked, only replaced by
rebuilding the entire PKI. Chosen (Phase 3b): root offline behind a
ceremony, `pathlen:1`; online intermediate with `pathlen:0` doing all
issuance; the service configured so it *cannot* name the root. Compromise
of the online tier becomes "revoke the intermediate and re-issue" — an
incident, not an extinction event. The cost — a ceremony step and a
two-certificate chain for relying parties — is the industry-standard cost,
paid everywhere real PKI runs. The ceremony as an operator runs it, the
manifest it produces, and the recovery path for each tier if a token is
lost are in [`key-ceremony-and-recovery.md`](key-ceremony-and-recovery.md).

### Durable revocation state rather than an in-memory registry
Rejected: keeping the Phase 2 in-memory registry past the phase that
scoped it. It was the correct Phase 2 simplification, but as a lasting
state it means a process restart silently erases revocations — a
certificate revoked for incident response reappears as valid, which is the
Phase 2.5 CRL-cache bug's lesson one level up. Chosen (Phase 3b): a small
embedded store behind an interface, holding issued/revoked records and the
CRL number counter, with a restart regression test. This also converts the
"stateless service, external state" note below from aspiration to fact.

### Keys with lifecycles rather than immortal labels
Rejected: provisioning signing keys under bare labels
(`image-signing-key`) with a single published PEM per key. It works until
the first rotation, at which point every consumer — cosign configs,
admission policies, docs — must change at once, so in practice the
rotation never happens. Chosen (CLAUDE.md §3.7, applied from Phase 4.8's
first provisioning): versioned labels plus a signed key inventory that
verifiers consume, giving each key an explicit active → verify-only →
retired(destroyed) lifecycle. A rotation drill in CI is planned, not built. The
CA hierarchy's own rotation — intermediate re-issue as the routine case,
root roll-over with cross-signing as the exceptional one — is documented
design in [`key-ceremony-and-recovery.md`](key-ceremony-and-recovery.md).

### No PKCS#11 module inside the service image
Rejected: installing SoftHSM2 into the image and mounting only the
proprietary vendor modules over it. That is what the licensing constraint
alone would suggest — SoftHSM2 is BSD-2-Clause and redistributable,
ProtectToolkit is not — and it keeps `docker run` self-contained, which is
worth something to a reader. Chosen (Phase 4): **no module of any kind ships
in the image**; every module, SoftHSM2 included, is mounted read-only at run
time. Reason: the rejected shape delivers the backend CI exercises
differently from the backend production uses, and a difference between
backends is precisely where this repository has already been bitten — the
`CKA_SENSITIVE` defect existed for the life of the project because one
backend could not see it (§2.4 of `CLAUDE.md`). Building that same asymmetry
into the packaging would be self-defeating. Two things fall out of it: the
published artifact contains no key store at all, and adding a vendor is a
mount plus a config value rather than a Dockerfile change.

The measured consequence is that the runtime base is sized for what gets
*mounted into* the image rather than for what it ships: a mounted module is
`dlopen`ed into the service's own address space, so `libsofthsm2.so` being
C++ forces `distroless/cc` (which carries `libstdc++`) where the service's
own cgo binary would have been content with `distroless/base`. The accepted
cost is that the image cannot start alone, which moves the burden of this
repository's zero-hardware reproducibility promise onto
`deploy/docker/run-local.sh` rather than removing it.

### cosign rather than a first-party signing tool
Rejected: a bespoke CLI over the Phase 1 `crypto.Signer`. It would demonstrate
the core more directly and would keep the PIN inside `SecurePIN`, but it would
also mean inventing a signature envelope: Go's standard library has no
CMS/PKCS#7, and importing an unaudited third-party one is exactly what
`CLAUDE.md` §3.3 forbids. A format nobody else can verify is not a signature
story, it is a private checksum. Rejected too: signing cosign's payload
ourselves and using `cosign attach signature` — that keeps the standard
artifact layout but hand-builds the payload, which is all of the divergence
risk for none of the simplicity.

Chosen: cosign for both images and artifacts, with the keys provisioned and
governed through the Phase 1 core, plus an independent `crypto/ecdsa`
cross-check in Go that verifies the signature bytes rather than trusting the
tool — the same move Phase 1.5 made against the HSM itself. The accepted cost
is that PKCS#11 support lives behind cosign's `pkcs11key` build tag, so the
pipeline must use the `pivkey-pkcs11key` release build rather than the default
binary, and the PIN passes through a process whose memory hygiene this
repository does not control — which is why it is supplied by environment
variable and never inside a PKCS#11 URI, where it would reach `ps` output,
shell history, and CI logs.

### OpenTofu on Hostinger, an imported VPS, and plan-only staging
Chosen (Phase 3): OpenTofu (not Terraform — HashiCorp's BSL relicensing is
worse licensing/governance for an open, cleanly-provenanced portfolio
piece than the Linux Foundation-governed fork) manages the maintainer's
existing Hostinger VPS via `tofu import`, never `tofu apply` creating one.
Rejected: a fresh, disposable VPS — an added monthly cost for a
destroy/replace risk that a structural safeguard already closes for free.
Chosen instead: `lifecycle { prevent_destroy = true }` on the imported
resource, turning any plan that would destroy or replace this
personally-used machine into a hard error rather than a live risk.
Rejected too: a second, real VPS to prove `environments/staging`
end-to-end — cost, for a phase whose acceptance criteria only need the
mechanism (identical modules, differing `.tfvars`) demonstrated, which
`tofu plan` alone already proves; staging stays plan-only, revisited if a
cheap second VPS becomes available. State itself: self-hosted MinIO on
the same VPS (locking via OpenTofu's native S3 conditional-write lock,
encryption via OpenTofu's own client-side `encryption` block) rather than
a second commercial account (Cloudflare R2) or HashiCorp's own Terraform
Cloud — the latter rejected specifically because routing state through
HashiCorp's SaaS a phase after leaving Terraform over its licensing would
read as inconsistent. Full reasoning:
[`docs/terraform-state-backend-setup.md`](terraform-state-backend-setup.md).

---

## Scalability and production-readiness notes

- **Stateless service, external state.** Key material lives in the HSM/Vault;
  issued/revoked records and the CRL number counter live in an embedded
  SQLite store behind the `internal/store.Store` interface (Phase 3b.3), so
  a restart no longer erases revocations. The store is single-writer by
  design at this scale — the connection pool is capped at one, which removes
  `SQLITE_BUSY` as a failure mode rather than managing it with retries. If
  replicas ever exist it moves to an external database, which is the swap
  the interface exists to permit; adding connections here is not that swap.
  The in-memory implementation alongside it is for tests only and nothing in
  `cmd/` constructs it.
- **Single-instance, deliberately, until two things change.** Not just
  because the store is single-writer: the generated CRL is cached
  per-process, so a revocation on one instance would leave another serving a
  CRL that omits it until `nextUpdate`. Running more than one replica needs
  shared state *and* cross-instance cache invalidation, not just a bigger
  connection pool. Phase 4 pins `replicas: 1` and says why in the manifest.
- **Immutable artifacts.** The deployed unit is a scanned, versioned container
  image. Rollback is "deploy the previous image," not "undo by hand."
- **Everything reproducible from code.** Infrastructure, deployment, and pipeline
  are all code; the environment rebuilds from the repo.
- **Observability is first-class.** Structured logs (never containing secrets) and
  health/readiness endpoints are part of the service contract so it behaves under
  an orchestrator.

---
