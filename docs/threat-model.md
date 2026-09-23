# Threat model

This document states what this platform protects, from whom, and what it
does not protect against. It is written for someone who knows security but
not this codebase. Every claim about what an attacker cannot do should be
traceable to a specific mechanism in the code. Every claim that is not yet
true is labelled as such.

**Status on 2026-09-21.** The platform has a two-tier CA with an offline
root, durable revocation state, a published CRL, a containerized
deployment whose cluster refuses unsigned and unpinned images, a pipeline
that signs every build of `main` keyless, and **mutual TLS on the write
endpoints**, with the clients authorised by name from certificates this
CA issued, certificate profiles, so every certificate is issued under a
stated policy, and a per-identity binding of profiles and names, so each
issuer may obtain only what it was granted, and a delegated OCSP
responder answering from the same store as the CRL. It has no audit log
and no Vault custody. §8 says what planned work changes.

---

## 1. How to read this

A threat model is only useful if it distinguishes three things:

- **What an attacker gains.** The concrete capability, not the label.
  "Gets the intermediate key" is a label. "Can issue a certificate for any
  name, trusted by every relying party that trusts the root, until the
  intermediate is revoked and that revocation is fetched" is a capability.
- **What it costs to recover.** Compromises that differ only in recovery
  cost are not the same compromise. Revoking an intermediate is an
  incident. Replacing a root is rebuilding every trust store that holds it.
- **What the attacker still cannot do.** This is the part that justifies
  the design. If compromising the service pod yields everything, the
  two-tier hierarchy bought nothing.

---

## 2. Assets

Ordered by what their loss costs.

| Asset | Where it lives | Loss means |
|---|---|---|
| `ca-root-key-vN` | Offline token, separate from everything else | Every certificate this PKI has ever issued becomes untrustworthy. A root cannot be revoked. A CRL signed by the compromised key is not evidence of anything, so recovery is distributing a new root to every relying party out of band. |
| `ca-intermediate-key-vN` | Online token, authenticated by the service | An attacker issues certificates trusted by anyone trusting the root, until the intermediate is revoked and that revocation reaches relying parties. |
| `image-signing-key-vN`, `artifact-signing-key-vN` | Supply-chain token, separate from the CA's tokens (§6.1) | Forged container images pass admission. Forged release artifacts pass the release verifier. |
| `inventory-signing-key-vN` | Offline inventory token | The attacker publishes their own list of trusted keys, and every verifier that holds the anchor accepts it. |
| `audit-signing-key-vN` | Not yet provisioned | The audit chain can be rewritten, so no other compromise leaves reliable evidence. |
| Token user PINs | Environment variables, read at the point of use | A PIN authenticates the token, so it is equivalent to holding every key on that token. See §6.1. |
| Revocation state | `ca.store_path`, embedded SQLite | A revoked certificate silently becomes valid again. This is why the store is required with no in-memory fallback. |
| The CRL publication channel | `GET /crl`, `GET /root.crl` | Not a secret, and still an asset. A relying party that cannot fetch a CRL concludes revocation is unavailable and usually proceeds. Availability of this channel is a security property (§6.2). |

Two assets are not on this list because the design prevents them from
existing: a private key in a file or a backup (keys are generated on the
token and never extractable), and a PIN in a config file or image (config
carries the name of an environment variable, never a value).

---

## 3. Trust boundaries

```
                    ┌───────────────────────────────────────────┐
   INTERNET ────────┤ B1: the public surface, plain HTTP        │
   (unauthenticated)│  GET /crl, /root.crl, /intermediate.crt,  │
                    │  /root.crt, /healthz, /readyz. No write   │
                    │  endpoint is routed here at all.          │
                    ├───────────────────────────────────────────┤
   OPERATORS ───────┤ B1': the authenticated surface, mutual TLS│
   (client cert     │  POST /certificates, /revoke. The client  │
    this CA issued) │  must chain to the root, be in the store  │
                    │  as issued and unrevoked, and be named in │
                    │  api.issuers or api.revokers.             │
                    └───────────────────┬───────────────────────┘
                                        │
                    ┌───────────────────▼───────────────────────┐
                    │ B2: the service process                   │
                    │  hsm-pki-server, holds the anchor login   │
                    │  on the ONLINE token for its lifetime     │
                    └───────┬───────────────────────┬───────────┘
                            │                       │
            ┌───────────────▼──────────┐   ┌────────▼─────────────┐
            │ B3: the online token     │   │ B4: the store        │
            │  ca-intermediate-key-vN  │   │  issued + revoked    │
            │  and nothing else (§6.1) │   │  records, CRL number │
            └──────────────────────────┘   └──────────────────────┘

    ═══════════════ no path crosses this line at runtime ═══════════════

            ┌──────────────────────────────────────────────────┐
            │ B5: the offline root token                       │
            │  ca-root-key-vN, reachable only from             │
            │  cmd/hsm-pki-keytool, run by an operator,        │
            │  never named by the service's configuration      │
            └──────────────────────────────────────────────────┘

            ┌──────────────────────────────────────────────────┐
            │ B6: CI/CD. Builds images, signs them keyless,    │
            │  and proves the PKCS#11 path against a throwaway │
            │  token and registry. Holds no durable key.       │
            └──────────────────────────────────────────────────┘

            ┌──────────────────────────────────────────────────┐
            │ B7: the admission webhook                        │
            │  Kyverno, cluster-wide. Decides what may run:    │
            │  signed by an inventory key, named by digest,    │
            │  hardened. Enforced everywhere EXCEPT the four   │
            │  namespaces its namespaceSelector excludes.      │
            └──────────────────────────────────────────────────┘
```

The line above B5 is the boundary the two-tier hierarchy exists to
create. It is enforced structurally: `internal/config.CAConfig` has no
field capable of naming the root's token, workspace, or key label, and
`TestConfig_NoRootKeyReferences` fails the build if one is added. A
compromised service process cannot authenticate a token it cannot name.

**B7 is a different kind of boundary from the rest.** B2 to B5 are
enforced by what a process can name. The service cannot log into a token
whose label its configuration cannot express, so the boundary holds even
against arbitrary code execution. B7 is enforced by a webhook the API
server consults, an authorization check the cluster performs on request.
Three consequences follow, and each is an attacker capability:

- **The boundary is scoped by namespace, not by cluster.** Both image
  policies carry a `namespaceSelector` excluding `kube-system`,
  `kube-public`, `kube-node-lease` and `kyverno`. Inside those four,
  nothing checks signatures or digests. See A9.
- **The boundary can be deleted, and deleting it is a normal-looking
  action.** `kubectl delete validatingwebhookconfiguration`, or deleting
  the Kyverno deployment or its namespace, removes the control for the
  whole cluster in one request that needs no access to any token, key or
  PIN. `failurePolicy: Fail` makes Kyverno being broken fail closed.
  Nothing makes Kyverno being absent fail closed, because a webhook that
  is not registered is not consulted. Recovery is cheap (re-apply the
  policies). Noticing is the real cost: after deletion the cluster accepts
  unsigned images silently, and admission leaves no denial to alert on.
  The planned audit chain is where this becomes evidenced. Today it is
  not.
- **The boundary trusts what the registry tells it.** The committed policy
  speaks HTTPS. The dev overlay renders its own copy with
  `-allow-insecure-registry` because the k3d registry speaks plaintext
  HTTP. See A9's note on the concession.

---

## 4. Attacker classes

| | Attacker | Assumed capability |
|---|---|---|
| **A1** | Unauthenticated network client | Can reach the HTTP API and send arbitrary requests |
| **A2** | Legitimate requester | As A1, plus valid credentials once authentication exists |
| **A3** | Compromised service process | Arbitrary code execution as `hsm-pki-server`, inheriting its anchor login |
| **A4** | Host root | Full control of the CA host: memory, disk, environment, the PKCS#11 module itself |
| **A5** | Compromised CI pipeline | Can run arbitrary build steps with whatever credentials CI holds |
| **A6** | Thief of storage | Has the token directory, a backup, or the HSM's storage media, but not the PIN |
| **A7** | Malicious operator | Authorized ceremony participant, knows PINs, has physical access |
| **A8** | Network position | Can intercept or block traffic between a relying party and this service |
| **A9** | Cluster tenant | Can create pods in the cluster, with whatever namespaces RBAC grants them |
| **A10** | Writer to this source repository | Can push a branch and merge it to `main`. No pull-request review is required |

---

## 5. What each attacker gets, and does not

### A1: Unauthenticated network client

**Gets:** the public artifacts, which are public: the two CRLs, the two
CA certificates, and the probe answers. Nothing else. The write endpoints
are not routed on the plain listener, so there is no request an
unauthenticated client can make that reaches `Issue` or the store. On the
authenticated listener the handshake itself refuses a client with no
certificate, or with one that does not chain to the ceremony root, before
any handler runs.

**Does not get:** a certificate, a revocation, any key material, or any
answer from the store. Before 2026-09-21 this attacker got a certificate
for any subject and any SAN, and could revoke any serial it knew. That
was the largest gap in the platform and it is closed. The residual is
denial: an attacker who can reach the public port can fetch the CRL as
often as it likes, and the CRL is cached per process (§6.2).

### A2: Legitimate requester

An A2 holds a certificate this CA issued, still valid in the store, whose
URI SAN or common name appears in `api.issuers` or `api.revokers`. The
first such certificate is issued by the operator with the keytool before
the service is up, over the intermediate token; every later one is issued
through the API by an issuer.

**Gets:** with an issuer identity, a certificate under a profile it was
granted, carrying only names that match the patterns it was granted;
with a revoker identity, the revocation of any serial. Profiles bound
the *shape*: a `tls-client` certificate cannot carry `serverAuth`, a
`tls-server` certificate cannot carry a URI name, and no profile copies
a subject attribute it does not list. The binding bounds the *name*: an
issuer granted `uri:urn:hsm-pki:team-b:*` cannot mint a `tls-client`
certificate carrying another issuer's identity, or a revoker's, because
the request is refused whole. The two lists separate the two
operations; profiles separate the kinds of certificate; the binding
separates issuers from each other. What remains is what the binding
cannot express: an issuer granted `dns:*.example.test` may name any
host under it, including one it does not operate, and nothing here
checks that a requester controls a name (there is no ACME-style
challenge). Revocation is not bound to who issued: any revoker may
withdraw any certificate, which is the intended shape for an incident.

**Does not get:** anything the CSR could choose that `Issue` sets from
policy: serial, validity window, key usage, CA status. A revoked issuer
gets nothing on its next request: the service reads its own store, not a
CRL, so revocation of a client takes effect at once with no fetch in
between. An A2 whose certificate was issued by another intermediate under
the same root gets nothing either, because the store has no record of
it.

**What the check is, precisely.** The TLS layer verifies the chain to
the root and requires the `clientAuth` extended key usage. The handler
then looks the leaf's serial up in the store, refuses an unknown serial,
refuses a record whose subject differs from the leaf's, refuses a revoked
one, and only then compares the leaf's identities against the list for
that endpoint. The service's own TLS identity is a leaf this CA issued
over a key held on the intermediate's token under its own label, and
`config` refuses a configuration that names the intermediate's key as
the TLS key: a handshake signs bytes the peer chooses, and the key that
signs certificates must never do that.

### A3: Compromised service process, the central case

This is the compromise the two-tier hierarchy was designed against.

**Gets:** use of the intermediate key for as long as the process lives.
PKCS#11 authenticates a token to an application, and the service holds
that login for its whole lifetime (the anchor login), so an attacker with
code execution does not need the PIN. The session is already
authenticated. Concretely: issue arbitrary certificates under the
intermediate, sign arbitrary CRLs including ones that omit real
revocations, and read or corrupt the store.

**Does not get:**

- **The root key.** It is on a token this process never names and never
  authenticates (B5). This is the difference between an incident and an
  extinction event. The response is to revoke the intermediate through the
  root's CRL and re-issue it, not to rebuild every trust store.
- **The intermediate's private key itself.** Keys are generated on the
  token with `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`, so the
  attacker can use the key while they hold the process, but cannot walk
  away with it. Eviction ends the capability.

  Both attributes are load-bearing and neither implies the other. Writing
  this document prompted checking them. The check found that
  `CKA_SENSITIVE` had been false on every key this platform had generated.
  On ProtectToolkit-C 7.3.3 software emulation the private scalar was
  readable by any authenticated session, so an attacker at A3 could have
  taken the key and kept using it after eviction. SoftHSM2 refused to
  disclose it, so CI was green throughout. It is fixed and asserted
  against both backends by reading the attributes back off the token
  ([`test-matrix.md`](test-matrix.md), "Expected divergences to look
  for").
- **The ability to issue a CA certificate.** The intermediate carries
  `pathlen:0`, enforced by every compliant verifier. An attacker who
  issues a sub-CA produces a certificate that fails path validation
  everywhere.
- **The ability to rewrite history**, once the planned audit chain exists
  and its key is held per §6.1's conclusion.

**Recovery:** revoke the intermediate (root CRL, ceremony), re-issue,
redeploy. Every certificate the attacker issued is invalidated with it.

### A4: Host root

**Gets:** everything A3 gets, plus the PIN as it passes through the
environment, plus the token directory for a software token, plus the
ability to substitute the PKCS#11 module itself.

**Does not get:** the root key, for the same structural reason. It is not
on this host at all. Against a hardware HSM it also does not get the
intermediate key as material, only its use while the host is held.

**Limit:** this platform does not defend the online tier against host
root. Nothing at this layer can. The defence is that the root is
elsewhere, so a fully compromised CA host is still a recoverable event.

### A5: Compromised CI pipeline

**Gets:** everything the publish job holds for the length of a run: a
registry credential that can push to GHCR, and the run's OIDC identity,
with which cosign obtains a Fulcio certificate. The attacker can push any
image and sign it keyless as the workflow, with attestations that say
whatever the attacker wants. Rekor records each signature publicly.

**Does not get: an image that admission accepts, or that
`ci/verify-release.sh` accepts.** Nothing CI holds is in the key
inventory. The PKCS#11 keys the mechanism test provisions die with the
runner and are not listed. The keyless signature is made under the
workflow identity, and the inventory lists keys, not identities, so
admission ignores it. The durable signature needs `image-signing-key-v1`
on the maintainer's token, which no pipeline can reach. This is the main
argument for keeping the durable signature off the pipeline: a compromised
CI can publish, but it cannot make anything deployable.

**Also does not get:** the CA hierarchy's keys, for the reason in §6.1.

**Recovery:** revoke the run's credentials by ending it, delete the pushed
digests, and note that the Rekor entries stay. No key rotation is needed,
because no key was held.

### A6: Thief of storage

**Gets:** ciphertext. For SoftHSM2, the token directory without the PIN.
For a hardware HSM, media whose keys are non-extractable by construction.

**Does not get:** usable keys. The wrap-based backup design must preserve
this: keys leave a token only wrapped under another HSM-held key, never in
the clear, and never in bulk.

### A7: Malicious operator

**Gets:** the root, during a ceremony. This is the one attacker the
cryptography cannot stop, because the ceremony's whole purpose is to give
an authorized human controlled access to the root key.

**Does not get:** deniability. The mitigation is procedural: multi-person
control, a written ceremony record, and the ceremony manifest that ties a
key to a token serial and a timestamp, so a later operator can tell
whether they are looking at the same token the root was generated on.

**Limit:** single-operator ceremonies, which is what this repository
demonstrates, provide no separation of duties. A production deployment
needs quorum (nShield ACS, Luna cloning domains). That is documented
design, not something this repository has run.

### A8: Network position

**Gets:** the ability to **block** CRL fetches and OCSP queries. A
relying party that
cannot fetch a CRL typically treats revocation as unavailable and
proceeds, so blocking the CDP is a cheap way to keep a revoked certificate
working.

**Does not get:** the ability to forge a CRL or a certificate. Both are
signed, and a modified one fails signature verification. The attacker's
only move against revocation is denial.

### A9: Cluster tenant

**Gets, if RBAC lets them create a pod in `kube-system`, `kube-public`,
`kube-node-lease` or `kyverno`: a complete bypass of image policy.** Both
`require-signed-images` and `require-image-digest` carry a
`namespaceSelector` that excludes exactly those four namespaces. A pod
created there runs an image nobody signed, named by a mutable tag, and
admission raises no objection, because the policy never matched the
request. Pod hardening is excluded in the same way. The bypass needs no
signing key, no PIN, no token access and no defect in Kyverno. It is the
policy's stated scope, used as written.

The exclusions are what lets the cluster boot. Kyverno cannot verify the
signature on its own image before it is running, and the control-plane's
static pods are not this repository's to sign. The alternative to
excluding them is a cluster that deadlocks at startup. The exclusion is a
permanent hole, which is why it belongs in this document: **whoever can
create pods in those four namespaces is outside the image-signing control
entirely, and the defence is Kubernetes RBAC, not anything this repository
enforces.** This platform ships no RBAC restricting who may create pods
there. The one RBAC file it does ship, `deploy/k8s/policy/kyverno-rbac.yaml`,
grants Kyverno's reports controller a permission it needs.

**Also gets, in the dev overlay only: whatever the network can
impersonate.** `deploy/k8s/overlays/dev/k3d-up.sh` renders the image
policy with `-allow-insecure-registry`, because the local k3d registry
speaks plaintext HTTP. Over plaintext there is no way to distinguish the
registry from anyone able to answer on its address, so the signature
Kyverno checks is whatever that party served. The verification still
runs, against an attacker's choice of input. The committed
`deploy/k8s/policy/image-signature.yaml` does **not** carry this
concession, and the generator requires the flag to be passed explicitly,
so the dev cluster's weaker posture cannot be reached by applying anything
in this repository. A real registry must speak TLS.

**Does not get:** any CA capability. Running an arbitrary image in an
excluded namespace is A3 at best. It still faces B2 to B5, so it does not
reach the intermediate key without the anchor login, and does not reach
the root key at all. The image-policy bypass is a supply-chain control
failure, not a key-custody one, and the two-tier hierarchy keeps those
separate.

**Limit:** the platform detects none of this. An unsigned image running in
`kube-system` produces no admission denial, no audit record and no alert.
The planned audit chain is where that gap is addressed.

### A10: Writer to this source repository

**Assumed capability, as the controls stand on 2026-09-10.** `main` is
protected: seven required checks, `enforce_admins` on, no force-push, no
deletion. **Pull-request review is not required**, on this repository or
on the anchor repository. A writer can open a pull request, wait for the
checks, and merge it alone. Repository variables and secrets need admin
access, which this attacker is assumed not to have.

**Gets:**

- Any change to the code, the workflow, the scripts and `docs/keys/` that
  passes the seven checks. The checks read the tree the attacker wrote.
- A build of `main` published by the pipeline and signed keyless under the
  workflow identity, with attestations. That signature says the workflow
  built it, which is true.
- The three anchor values printed in the README. A consumer who copies
  them from there instead of holding them independently accepts whatever
  the attacker wrote, and `ci/verify-release.sh` then verifies an
  attacker's inventory for that consumer. This is the residual the README
  states.

**Does not get:**

- An image that admission accepts, or that a consumer holding the real
  anchor inputs accepts. The durable signature needs
  `image-signing-key-v1` on the maintainer's token, and the inventory that
  lists it is signed by an offline token whose public half the attacker
  cannot change in place. That file lives in the anchor repository, where
  force-pushes are refused.
- A change to what the trust-chain check compares against. The anchor
  inputs come from repository variables, not from the tree.
- The CA hierarchy's keys, or any token.

**Recovery:** revert the merge. Digests the pipeline published in the
meantime carry a keyless signature that names the run, and Rekor keeps a
public record of it.

---

## 6. Findings this model produced

These came out of writing it.

### 6.1 A token login authenticates a token, not a key, so purpose-separated keys need separated tokens

Purpose separation says a compromised image key must not be able to issue
a certificate, and a compromised CA key must not be able to sign a
release. Distinct labels and `CKA_ID`s achieve that against accidental
reuse. They do not achieve it against an attacker, because PKCS#11
authentication is per token. Any process holding a session on a token can
find every key on it by label and sign with it.

An earlier signing-layer design placed `ca-intermediate-key-v1`,
`image-signing-key-v1` and `artifact-signing-key-v1` on one online token.
With that layout, A3 (compromise of the CA daemon) also yields image and
artifact signing, and the blast-radius separation holds against mistakes
and not against the attacker it names.

This is the same reasoning that put the root on its own token, applied one
tier down. **The supply-chain keys are provisioned on a third, separate
token**, so A3 yields the intermediate and nothing else.

**A fourth token exists for the same reason one tier further up.** The
key inventory is the document that tells every verifier which keys to
trust, so whoever can sign it can authorise their own signatures. Signing
it with a key on the supply-chain token would make the list vouch for a
token that vouches for itself. Signing it with the CA intermediate would
put it back inside A3. `inventory-signing-key-v1` sits on an offline token
of its own, holding none of the keys it names. That is the invariant
TUF's offline root role and any offline X.509 root are built on. It has
its own token rather than the CA root's because the root's token is opened
for a ceremony and nothing else. Anchoring the inventory there would turn
every supply-chain rotation into a root-token access, and a control that
expensive gets skipped.

What this does not buy: A4 (host root) still reaches every token whose PIN
is on the same host. A token only a release process can reach remains the
stronger end state, reachable from here as a deployment change. The
inventory token is the one furthest from that problem, because it is only
mounted when a rotation is being published.

### 6.2 The revocation channel's availability is a security property

Blocking a CRL fetch (A8) and serving a CRL nobody can parse produce the
same outcome at the relying party: revocation unavailable, proceed anyway.
The second was a shipped defect, where `/root.crl` served PEM at a
distribution point OpenSSL could not read. It is fixed. The first is an
attacker capability that cannot be removed. Both argue for the same
things: short CRL lifetimes, and OCSP with stapling so freshness rides on
the connection rather than on a separate fetch the attacker can cut.

### 6.3 PIN handling: one copy is outside this code

The service reads the PIN from an environment variable at the point of use
and copies it into a `SecurePIN`, a buffer allocated with `C.malloc`. The
Go garbage collector does not move or copy that buffer, so it can be
zeroed after `C_Login` and the zeroing is known to reach it. The Go-heap
slice the PIN arrived in is zeroed as well, on every path.

That is not the whole story. The PIN reaches `miekg/pkcs11` v1.1.2 as a Go
string. Its `Login` calls `C.CString`, which allocates a second C buffer,
passes it to `C_Login`, and frees it without zeroing. That buffer is
outside this repository's control. After a login the PIN can remain in
freed C heap until the allocator reuses it.

Two options:

1. Fork the binding so that `Login` takes a `[]byte` and zeroes its C
   buffer before freeing it. This removes the copy. It costs a fork of a
   dependency that this repository would then maintain.
2. Accept the residual. The window is the time between `C_Login`
   returning and the freed memory being reused. An attacker able to read
   freed C heap inside the process is A3, and A3 already holds an
   authenticated token (§5). The residual adds nothing to what A3 can do.

The residual is accepted. The fork is not implemented.

---

## 7. Non-goals

A threat model that claims everything is defended is not a threat model:

- **Defending the online tier against host root or a compromised
  process.** The design bounds that blast radius. It does not prevent it.
- **Separation of duties for ceremonies.** Single-operator, by
  construction, in this repository (§A7).
- **Availability and DoS resistance.** Rate limiting, quotas, and capacity
  are out of scope. The one availability property treated as
  security-relevant is the revocation channel (§6.2).
- **Side-channel resistance.** Delegated to the HSM and to the standard
  library. This platform performs no private-key arithmetic itself.
- **Multi-tenancy.** There is no tenant model and no per-tenant isolation.
- **Supply chain of the dependencies themselves.** Scanned, not proven.
- **Protecting against the HSM vendor or the PKCS#11 module.** A malicious
  module sees every PIN and every operation. The multi-vendor abstraction
  makes swapping one cheaper. It does not make one trustworthy.

---

## 8. What planned work changes

| Work | Changes for this model |
|---|---|
| **Certificate profiles and OCSP** | Profiles bound what A2 can obtain, and separate issuers from each other. OCSP narrows A8's blocking window. |
| **Vault custody** | Changes where the intermediate lives and what a compromised service can reach. The custody decision must be made against this model. |
| **The audit chain** | Makes compromises evidenced. Its key must not be reachable by the process it audits (§6.1). A deleted webhook (B7) and an excluded-namespace bypass (A9) become visible. |

---

## 9. Cross-references

- Blast-radius reasoning behind the design:
  [`architecture.md`](architecture.md), "The signing layer" and "Two-tier
  hierarchy rather than a single online CA"
- The rules these conclusions follow: purpose-separated keys, fail closed,
  identity by serial and digest, verification by another implementation.
  [`architecture.md`](architecture.md), "Key design decisions", states
  them with their alternatives.
- Ceremony and recovery procedures, including the A7 manifest mitigation
  and the A6 wrap-based backup boundary:
  [`key-ceremony-and-recovery.md`](key-ceremony-and-recovery.md)
