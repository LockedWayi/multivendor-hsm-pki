# Threat model

This document states what this platform protects, from whom, and — just as
importantly — what it does not protect against. It is written to be read by
someone who knows security but not this codebase, and it is meant to be
falsifiable: every claim about what an attacker cannot do should be
traceable to a specific mechanism in the code, and every claim that is not
yet true is labelled as such rather than described in the present tense.

**Status: written at the end of Phase 3b** (sub-task 3b.5). The platform at
this point has a two-tier CA with an offline root, durable revocation state,
and a published CRL. It has **no authentication on the issuance API** —
that arrives in Phase 5.5 — and no OCSP responder, audit log, or Vault
custody yet. The analysis below reflects that reality; §8 says what each
later phase changes.

---

## 1. How to read this

A threat model is only useful if it distinguishes three things that are easy
to blur:

- **What an attacker gains.** The concrete capability, not the label. "Gets
  the intermediate key" is a label; "can issue a certificate for any name,
  trusted by every relying party that trusts the root, until the
  intermediate is revoked and that revocation is fetched" is a capability.
- **What it costs to recover.** Compromises that differ only in recovery
  cost are not the same compromise. Revoking an intermediate is an incident;
  replacing a root is rebuilding every trust store that holds it.
- **What the attacker still cannot do.** This is the part that justifies the
  design. If compromising the service pod yields everything, the two-tier
  hierarchy bought nothing.

---

## 2. Assets

Ordered by what their loss costs, not by how interesting they are.

| Asset | Where it lives | Loss means |
|---|---|---|
| `ca-root-key-vN` | Offline token, separate from everything else | Every certificate this PKI has ever issued becomes untrustworthy. A root cannot be revoked — a CRL signed by the compromised key is not evidence of anything — so recovery is distributing a new root to every relying party out of band. |
| `ca-intermediate-key-vN` | Online token, authenticated by the service | An attacker issues certificates trusted by anyone trusting the root, until the intermediate is revoked *and* that revocation reaches relying parties. |
| `image-signing-key-vN`, `artifact-signing-key-vN` | Online token (Phase 4.8) | Forged container images pass admission; forged release artifacts pass the build gate. |
| `audit-signing-key-vN` | Phase 8, not yet provisioned | The audit chain can be rewritten, so no other compromise leaves reliable evidence. |
| Token user PINs | Environment variables, read at the point of use | Authenticates the token, so it is equivalent to holding every key on that token — see §6.1, which is the reason this row matters more than it looks. |
| Revocation state | `ca.store_path`, embedded SQLite | A revoked certificate silently becomes valid again. This is why the store is required with no in-memory fallback (Phase 3b.3). |
| The CRL publication channel | `GET /crl`, `GET /root.crl` | Not a secret, and still an asset: a relying party that cannot **fetch** a CRL concludes revocation is unavailable and usually proceeds. Availability of this channel is a security property, not an operational one (§6.5). |

Two assets that are deliberately *not* on this list, because the design
prevents them from existing: a private key in a file or a backup (keys are
generated on the token and never extractable), and a PIN in a config file or
image (config carries the name of an environment variable, never a value —
CLAUDE.md §3.1, §3.2).

---

## 3. Trust boundaries

```
                    ┌───────────────────────────────────────────┐
   INTERNET ────────┤ B1: the HTTP surface                      │
   (unauthenticated)│  POST /certificates, /revoke, GET /crl    │
                    │  no authentication until Phase 5.5        │
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
            │  (+ signing keys, §6.1)  │   │  records, CRL number │
            └──────────────────────────┘   └──────────────────────┘

    ═══════════════ no path crosses this line at runtime ═══════════════

            ┌──────────────────────────────────────────────────┐
            │ B5: the offline root token                       │
            │  ca-root-key-vN — reachable only from            │
            │  cmd/hsm-pki-keytool, run by an operator,        │
            │  never named by the service's configuration      │
            └──────────────────────────────────────────────────┘

            ┌──────────────────────────────────────────────────┐
            │ B6: CI/CD (Phase 5) — builds and signs images    │
            │  and artifacts with its own token session        │
            └──────────────────────────────────────────────────┘
```

The line above B5 is the boundary this whole phase exists to create, and it
is enforced structurally rather than by policy: `internal/config.CAConfig`
has no field capable of naming the root's token, workspace, or key label,
and `TestConfig_NoRootKeyReferences` fails the build if one is added. A
compromised service process cannot authenticate a token it cannot name.

---

## 4. Attacker classes

| | Attacker | Assumed capability |
|---|---|---|
| **A1** | Unauthenticated network client | Can reach the HTTP API and send arbitrary requests |
| **A2** | Legitimate requester | As A1, plus (from Phase 5.5) valid credentials |
| **A3** | Compromised service process | Arbitrary code execution as `hsm-pki-server`, inheriting its anchor login |
| **A4** | Host root | Full control of the CA host: memory, disk, environment, the PKCS#11 module itself |
| **A5** | Compromised CI pipeline | Can run arbitrary build steps with whatever credentials CI holds |
| **A6** | Thief of storage | Has the token directory, a backup, or the physical HSM media — but not the PIN |
| **A7** | Malicious operator | Authorized ceremony participant, knows PINs, has physical access |
| **A8** | Network position | Can intercept or block traffic between a relying party and this service |

---

## 5. What each attacker gets, and does not

### A1 — Unauthenticated network client

**Gets, today:** a valid certificate for any subject and any SAN it asks
for. This is the single largest open gap in the platform as of Phase 3b, and
it is a missing feature rather than a defect: `POST /certificates` has no
authentication until Phase 5.5. Anyone who can reach the port can obtain a
certificate signed by the intermediate.

It can also revoke any certificate whose serial it knows (`POST
/certificates/{serial}/revoke`), which is a denial-of-service against that
certificate's holder. Serials are 128-bit random, so this requires knowing
the serial — typically by having been issued the certificate, or by reading
one off a TLS handshake.

**Does not get:** any key material; the ability to choose its own serial,
validity window, key usage, or CA status (every one of those is set by
`Issue` from the CA's own policy, never from the CSR); the ability to have a
CSR with an unverifiable self-signature, an empty subject, or a weak key
accepted; or the ability to make the CA sign anything that is not a
certificate.

**Mitigation status:** deferred by design to Phase 5.5, which is why this
service is not exposed publicly before then. Until it lands, the deployment
boundary *is* the authentication boundary — an honest statement of a real
limitation, not a claim of safety.

### A2 — Legitimate requester (Phase 5.5 onward)

**Gets:** certificates within whatever profile and naming policy Phase 5b
grants its identity.

**Does not get:** certificates outside that policy — but only once Phase 5b
lands. Today there are no profiles: every leaf gets `serverAuth` **and**
`clientAuth`, and any subject the CSR asks for. Restricting that is
[Phase 5b's certificate-profile work](phases/phase-5b-issuance-policy-ocsp.md).

### A3 — Compromised service process ★ the central case

This is the compromise the two-tier hierarchy was designed against, so it
deserves the most precision.

**Gets:** use of the intermediate key for as long as the process lives.
PKCS#11 authenticates a token to an application, and the service holds that
login for its whole lifetime (the Phase 2.8 anchor login), so an attacker
with code execution does not need the PIN — the session is already
authenticated. Concretely: issue arbitrary certificates under the
intermediate, sign arbitrary CRLs including ones that *omit* real
revocations, and read or corrupt the store.

**Does not get:**

- **The root key.** It is on a token this process never names and never
  authenticates (B5). This is the difference between an incident and an
  extinction event: the response is to revoke the intermediate through the
  root's CRL and re-run the ceremony, not to rebuild every trust store.
- **The intermediate's private key itself.** Keys are generated on the token
  with `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`, so the attacker can
  *use* the key while they hold the process, but cannot walk away with it.
  Eviction ends the capability; it does not leave a copy behind.

  Both attributes are load-bearing and neither implies the other. Writing
  this document is what prompted checking them, and the check found that
  `CKA_SENSITIVE` had been false on every key this platform ever generated:
  on ProtectToolkit 7.3.3 the private scalar was readable by any
  authenticated session, which would have made this entire paragraph false
  — an attacker at A3 could have taken the key and kept using it after
  eviction. SoftHSM2 refused to disclose it, so CI was green throughout.
  Fixed and now asserted against both backends by reading the attributes
  back off the token
  ([`pkcs11-vendor-notes.md`](pkcs11-vendor-notes.md), "A non-sensitive
  private key really is readable here").
- **The ability to issue a CA certificate.** The intermediate carries
  `pathlen:0`, enforced by every compliant verifier, not by this code. An
  attacker who issues a sub-CA produces a certificate that fails path
  validation everywhere.
- **The ability to rewrite history** — once Phase 8's audit chain exists and
  its key is held per §6.1's conclusion.

**Recovery:** revoke the intermediate (root CRL, ceremony), re-issue,
redeploy. Every certificate the attacker issued is invalidated with it,
which is exactly what the hierarchy buys.

### A4 — Host root

**Gets:** everything A3 gets, plus the PIN as it passes through the
environment, plus the token directory for a software token, plus the ability
to substitute the PKCS#11 module itself.

**Does not get:** the root key, for the same structural reason — it is not
on this host at all. Against a hardware HSM it also does not get the
intermediate key as material, only its use while the host is held.

**Honest limit:** this platform does not defend the online tier against host
root. Nothing at this layer can — the defence is that the root is elsewhere,
so a fully compromised CA host is still a recoverable event.

### A5 — Compromised CI pipeline

**Gets (from Phase 4/5):** whatever the pipeline's own token session can
sign — image and artifact signatures, and therefore images that pass
admission.

**Does not get:** the CA hierarchy's keys, *provided* §6.1's conclusion is
implemented. This is the finding this document exists to surface, and it is
open.

### A6 — Thief of storage

**Gets:** ciphertext. For SoftHSM2, the token directory without the PIN; for
a hardware HSM, media whose keys are non-extractable by construction.

**Does not get:** usable keys. The wrap-based backup design (Phase 3b.6)
must preserve this: keys leave a token only wrapped under another HSM-held
key, never in the clear, and never in bulk.

### A7 — Malicious operator

**Gets:** the root, during a ceremony. This is the one attacker the
cryptography cannot stop, because the ceremony's whole purpose is to give an
authorized human controlled access to the root key.

**Does not get:** deniability. The mitigation is procedural rather than
technical — multi-person control, a written ceremony record, and the
ceremony manifest (Phase 3b.6) that ties a key to a token serial and a
timestamp so a later operator can tell whether they are looking at the same
token the root was generated on.

**Honest limit:** single-operator ceremonies, which is what this repository
demonstrates, provide no separation of duties. A production deployment needs
quorum (nShield ACS, Luna cloning domains); that is documented design, not
something this repo has run.

### A8 — Network position

**Gets:** the ability to **block** CRL fetches, which is the interesting
one. A relying party that cannot fetch a CRL typically treats revocation as
unavailable and proceeds — so blocking the CDP is a cheap way to keep a
revoked certificate working.

**Does not get:** the ability to forge a CRL or a certificate. Both are
signed, and a modified one fails signature verification. The attacker's only
move against revocation is denial, not falsification.

---

## 6. Findings this model produced

A threat model that only restates what the code already does has not earned
its place. These came out of writing it.

### 6.1 A token login authenticates a token, not a key — so purpose-separated keys need separated *tokens*

CLAUDE.md §3.6 separates signing keys by purpose so that "a compromised
image key must not be able to issue a certificate, a compromised CA key must
not be able to sign a release." Distinct labels and `CKA_ID`s achieve that
against *accidental* reuse. They do not achieve it against an attacker,
because PKCS#11 authentication is per token: any process holding a session
on a token can find every key on it by label and sign with it.

`docs/architecture.md`'s signing-layer diagram currently places
`ca-intermediate-key-v1`, `image-signing-key-v1` and `artifact-signing-key-v1`
on one online token. If that is what Phase 4.8 provisions, then A3 —
compromise of the CA daemon — also yields image and artifact signing, and
the blast-radius separation §3.6 describes is only half real: it holds
against mistakes and not against the attacker it names.

This is the same reasoning that put the root on its own token in Phase 3b,
applied one tier down. **Recorded as a decision Phase 4.8 must make before
provisioning those keys**, with the options and their costs, rather than
settled here.

### 6.2 The revocation channel's availability is a security property

Blocking a CRL fetch (A8) and serving a CRL nobody can parse (the Phase 3b.4
defect, where `/root.crl` served PEM at a distribution point OpenSSL could
not read) produce the *same* outcome at the relying party: revocation
unavailable, proceed anyway. The second was a bug we shipped and fixed; the
first is an attacker capability we cannot remove. Both argue for the same
things — short CRL lifetimes, and eventually OCSP with stapling (Phase 5b)
so freshness rides on the connection rather than on a separate fetch the
attacker can cut.

---

## 7. Non-goals

Stated plainly, because a threat model that claims everything is defended is
not a threat model:

- **Defending the online tier against host root or a compromised process.**
  The design bounds that blast radius; it does not prevent it.
- **Separation of duties for ceremonies.** Single-operator, by construction,
  in this repository (§A7).
- **Availability and DoS resistance.** Rate limiting, quotas, and capacity
  are out of scope. The one availability property treated as security-
  relevant is the revocation channel (§6.2).
- **Side-channel resistance.** Delegated to the HSM and to the standard
  library; this platform performs no private-key arithmetic itself.
- **Multi-tenancy.** There is no tenant model, no per-tenant isolation, and
  deliberately none (CLAUDE.md §1).
- **Supply chain of the dependencies themselves.** Scanned (Phase 3), not
  proven.
- **Protecting against the HSM vendor or the PKCS#11 module.** A malicious
  module sees every PIN and every operation. The multi-vendor abstraction
  makes swapping one cheaper; it does not make one trustworthy.

---

## 8. What later phases change

| Phase | Changes for this model |
|---|---|
| **4** | Provisions the image/artifact signing keys — must first settle §6.1's token layout. Containerization adds the pod boundary and the volume holding the store. |
| **5** | Authentication on the issuance API closes A1, the largest current gap. CI becomes A5, with real signing capability. |
| **5b** | Certificate profiles bound what A2 can obtain; OCSP narrows A8's blocking window. |
| **6** | Vault custody changes where the intermediate lives and what a compromised service can reach. The custody decision must be made against this model, not around it. |
| **8** | The audit chain makes compromises *evidenced*. Its key must not be reachable by the process it audits — §6.1 again, and the reason that finding matters beyond the signing keys. |

---

## 9. Cross-references

- Blast-radius reasoning behind the design: [`architecture.md`](architecture.md),
  "The signing layer" and "Two-tier hierarchy rather than a single online CA"
- The rules these conclusions are enforced by: [`../CLAUDE.md`](../CLAUDE.md) §3
- The hierarchy, the store, and the distribution points as built:
  [`phases/phase-3b-pki-hardening.md`](phases/phase-3b-pki-hardening.md)
- Ceremony and recovery procedures: `key-ceremony-and-recovery.md` (Phase 3b.6)
