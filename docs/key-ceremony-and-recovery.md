# Key ceremony and disaster recovery

Phase 3b sub-task 3b.6. The companion to [`threat-model.md`](threat-model.md):
that document says what an attacker gets and does not get; this one says what
an *operator* does — how the root and intermediate come into existence, what
record that leaves, and what to do when a token is lost, stolen, or simply
reaches the end of its rotation window.

## 1. How to read this

Three audiences, three sections:

- Running the root ceremony for the first time, or refreshing the root CRL:
  §2.
- A token was lost, destroyed, or is suspected compromised: §4.
- Designing what this platform does not yet build — wrap-based backup,
  vendor-native ceremony hardware, CA rotation: §5–§7, all labelled
  **documented-design** per CLAUDE.md §2.3 where they have not been run.

Every artifact this document describes is public: certificates and a CRL.
Nothing here ever writes a private key, a PIN, or a wrapped key blob to a
log line or a plaintext file (CLAUDE.md §3.1).

## 2. The root ceremony as an operator procedure

### 2.1 Who, and with what access

One operator, run locally against real hardware or the software emulator —
this repository demonstrates a **single-operator** ceremony, which
§7's non-goal in `threat-model.md` states plainly: it provides no separation
of duties. The operator needs:

- PINs for **two** tokens: the root's and the intermediate's
  (`docs/phases/phase-3b-pki-hardening.md`, "Where the root key lives
  relative to the intermediate"). Never the same token — `RunCeremony`
  refuses to run if the two workspaces resolve to the same serial.
- The vendor module path and adapter name (`softhsm2` or `protectserver`).
- Every certificate parameter decided **before** the ceremony starts,
  because a ceremony is irreversible (CLAUDE.md §3.9): subject names, the
  EC curve, and — the one that is easiest to get wrong — the root CRL and
  root certificate distribution URLs. Those two URLs are baked into the
  intermediate's extensions at signature time and can never be changed
  without bringing the offline root back out to re-sign. Validity periods
  are the one exception worth flagging: `CeremonyParams` supports
  `RootValidity`, `IntermediateValidity` and `RootCRLValidity`, but
  `hsm-pki-keytool ceremony` does not expose them as flags today — every
  ceremony run through the CLI gets the platform defaults (ten years,
  five years, five years) whether that is what the operator wanted or not.
  `CeremonyParams.validate()` still rejects an intermediate that would
  outlive its root even at the default values, so this is a missing
  option, not a missing safety check.

`cmd/hsm-pki-keytool`'s `ceremony` subcommand validates every one of these
before it generates the first key (`internal/ca/ceremony.go`,
`CeremonyParams.validate`) — a malformed URL or a validity mismatch is
rejected before any key exists on either token, not after.

### 2.2 Running it

```sh
hsm-pki-keytool ceremony \
  -adapter softhsm2 \
  -module /usr/lib/softhsm/libsofthsm2.so \
  -curve P-256 \
  -root-workspace hsm-pki-root -root-pin-env ROOT_PIN \
  -root-key-label ca-root-key-v1 \
  -root-cn "hsm-pki-platform Root CA" \
  -root-cert-out root.pem -root-crl-out root-crl.pem \
  -root-crl-url  https://pki.example.org/root.crl \
  -root-cert-url https://pki.example.org/root.crt \
  -root-key-extractable=true \
  -intermediate-workspace hsm-pki-dev -intermediate-pin-env INTER_PIN \
  -intermediate-key-label ca-intermediate-key-v1 \
  -intermediate-cn "hsm-pki-platform Intermediate CA" \
  -intermediate-cert-out intermediate.pem
```

Against ProtectServer, see
[`protectserver-setup.md`](protectserver-setup.md) §3b for provisioning the
two tokens and §3c for migrating a Phase 2-era single-tier token — there is
no upgrade path, by design; a single-tier key was never certified by a root,
so it cannot become an intermediate.

### 2.3 What comes out, and what does not

Three files, all PEM, all public:

- The root certificate (`pathlen:1`, self-signed).
- The intermediate certificate (`pathlen:0`, signed by the root), carrying
  the CDP and AIA extensions built from the two URLs above.
- The root's initial CRL — long-lived (`DefaultRootCRLValidity`, five
  years), covering exactly the intermediate, with zero revoked entries. The
  reasoning for a long-lived CRL rather than a recurring "root online"
  schedule is in `docs/phases/phase-3b-pki-hardening.md`, "How the root CRL
  is produced while the root is offline."

No private key material of any kind. Both key pairs are generated on, and
never leave, their respective tokens — `RunCeremony` asserts
`adapter.TokenLoggedIn() == false` after it returns, on every path, and the
CLI's success output prints that explicitly:

```
no private key material was written anywhere — both key pairs remain on their respective HSM tokens
root private key: CKA_EXTRACTABLE=true — eligible for wrap-based backup (docs/key-ceremony-and-recovery.md)
```

That second line is the operator-facing echo of §6.2's decision below —
printed so it is part of the ceremony's own record, not something an
operator has to separately remember they chose.

**Certificates are written before the error is checked, deliberately.** If
signing succeeds but the root token's logout then fails, the key pairs
already exist — the ceremony's own overwrite guard means a second attempt
cannot recreate them under the same labels — so discarding the certificates
at that point would be unrecoverable. `cmd/hsm-pki-keytool` writes the three
files first and reports the logout error alongside them.

### 2.4 Refreshing the root CRL

The root stays offline between ceremonies by design (§2.1), so there is no
"publish an updated root CRL" operation that does not involve the root
token. Refreshing it — extending its validity, or (see §4.2) actually
revoking the intermediate — means **running the ceremony again**: a fresh
root key, a fresh intermediate signed under it, a fresh CRL. This is not a
limitation to work around; it is the operational consequence of choosing a
long-lived CRL over a recurring "root online" moment
(`docs/phases/phase-3b-pki-hardening.md`), and it is why §4's disaster
recovery procedures and a routine CRL refresh are, mechanically, the same
event — the ceremony does not distinguish "the root's CRL is due for
renewal" from "the intermediate was compromised."

## 3. The ceremony manifest

### 3.1 What it is, and why it exists

A real key ceremony leaves a written record of what was produced, on which
physical token, by whom, and when — evidence a later operator uses to
confirm they are looking at the same token the root was generated on, not
one that merely shares its label (CLAUDE.md §3.8). `threat-model.md` §A7
names exactly why this matters: the one attacker the ceremony's own design
cannot stop is the operator running it, and the mitigation for that is
procedural, not cryptographic — a written record and, eventually,
multi-person control this repository does not implement (§7's non-goal).
The manifest is the written half.

### 3.2 Fields

Everything here is public — no PIN, no private key, no wrapped key blob:

| Field | Source | Why it is in the manifest |
|---|---|---|
| Root token label and serial | `pkcs11.Workspace` | Serial is identity, label is address (CLAUDE.md §3.8) — both are recorded so a later operator can resolve either |
| Intermediate token label and serial | `pkcs11.Workspace` | Same reasoning, other tier |
| Root key label | operator-supplied flag | What `C_FindObjects` resolves at signing time |
| Intermediate key label | operator-supplied flag | Same, intermediate tier |
| Root key `CKA_EXTRACTABLE` | `-root-key-extractable` | Whether this root is backup-eligible — see §6.2; a later operator must not have to re-derive this from the token itself when deciding whether a restore is even possible |
| Root certificate serial number | `CeremonyResult` (parsed) | The value a relying party's chain-building actually keys on |
| Intermediate certificate serial number | `CeremonyResult` (parsed) | Same, intermediate tier |
| Root and intermediate subject DNs | operator-supplied flags | What the certificates assert, for a human cross-check against what was intended |
| Root and intermediate validity windows | `CeremonyParams` (defaults or flags) | When each certificate — and therefore the chain — stops being valid |
| Root CRL validity | `CeremonyParams` (default or flag) | When the root's CRL must be refreshed (§2.4) |
| Root CRL URL / root certificate URL | operator-supplied flags | The values baked into the intermediate's extensions, irreversibly, at signature time |
| Timestamp | ceremony run time | When this happened, in absolute terms |
| Operator identity | outside this tool's scope | Who ran it — a procedural fact, not something PKCS#11 can attest to; recorded by whatever process wraps the ceremony (sign-off sheet, ticket, commit) |

### 3.3 Current state, and what is deferred

Not all of this is captured automatically today. Token labels, key labels,
the CDP/AIA URLs, and (since §5.2) the root's `CKA_EXTRACTABLE` choice are
either what the operator typed on the command line or printed by
`hsm-pki-keytool ceremony`'s own stdout (§2.3's output block). Certificate
serial numbers, subject DNs, and validity windows are **not** printed
anywhere today — the operator has to read them off the written PEM files
themselves (`openssl x509 -text -in root.pem`, and likewise for the
intermediate) and assemble the manifest by hand from the command line used,
the stdout output, and that inspection. What does not exist yet is a
**structured file** — JSON or YAML — that the ceremony emits automatically,
parsing its own output the way an operator currently has to. That is
recorded as a Phase 4.8 item (`docs/phases/phase-4-container-k8s.md`, "Emit
the ceremony manifest as a file, not just as printed output"), alongside
that phase's other `hsm-pki-keytool` extensions, rather than bolted onto
the CLI here ahead of the format being exercised by real use.

## 4. Disaster recovery, by tier

"Lost" covers the same set of events regardless of cause: the token is
destroyed, the hardware fails, or a compromise means the key can no longer
be trusted — `threat-model.md` A6 and A7 name the relevant attackers. The
recovery path differs by which tier is lost, and that difference is the
entire reason this platform has two tiers rather than one
(`docs/architecture.md`, "Two-tier hierarchy rather than a single online
CA").

### 4.1 Losing the intermediate token — the routine case

This is the incident the two-tier hierarchy exists to make cheap. The root
is untouched; every certificate the root ever signed, including the old
intermediate, is still valid until explicitly revoked. The recovery is:

1. Revoke the old intermediate on the root's CRL — which, per §2.4, means
   running the ceremony again, since the root is offline. The new run
   signs a *new* intermediate under a *new* root key, because `RunCeremony`
   generates both tiers together (see the gap noted in §4.1.1 below) — so
   today this path is mechanically identical to §4.2's "lose the root"
   path, even though the root itself was never touched.
2. Re-issue every leaf that was still validly issued under the old
   intermediate, under the new one. The service cannot do this
   automatically: a leaf's issuer is fixed at signature time (CLAUDE.md
   §3.9), so this is a re-issuance campaign, not a configuration change.
3. Point the service at the new intermediate certificate and key label
   (`ca.intermediate_cert_path`, `ca.intermediate_key_label`) and restart —
   `ca.LoadIntermediate`'s startup checks (`docs/phases/
   phase-3b-pki-hardening.md`, 3b.2) refuse to start against anything that
   is not a validly-chained, non-self-signed, correctly-`pathlen:0`
   certificate whose public key matches the configured key label, so a
   mismatched pairing fails loudly at startup rather than issuing
   certificates nothing can verify.

#### 4.1.1 The gap: there is no "re-issue the intermediate alone" path yet

CLAUDE.md §3.7 describes the intermediate rotating by "re-issuing the
intermediate (routine)" — implying the root key is *reused*, not
regenerated, for what should be the cheap, frequent case. `RunCeremony`
does not support that today: `signRootAndIntermediate`
(`internal/ca/ceremony.go`) always calls `GenerateKeyPair` for the root, so
every ceremony run mints a fresh root whether one was needed or not. Until
a `reissue-intermediate` subcommand exists (tracked in
`docs/phases/phase-4-container-k8s.md`, 4.8), losing *only* the
intermediate token is handled exactly like §4.2 — which is safe (nothing
about re-running the full ceremony is incorrect) but more expensive than it
needs to be: every relying party that pinned the old root now has to trust
a new one, for an incident that never touched the root at all.

### 4.2 Losing the root token — the exceptional case

The root cannot be recovered from a backup unless §6's wrap-based design
was actually used for it (§6.2 — an explicit, per-ceremony operator
choice, not a given). Absent that, recovery is a **fresh ceremony**: a new
root key, on a new or wiped token, and a decision about the existing
intermediate:

- **Cross-sign it.** Have the new root also sign the *existing* intermediate
  certificate's public key, producing a second intermediate certificate
  (same key, same subject, a different issuer and serial) that chains to
  the new root. Relying parties that already trust the old root keep
  working through the old chain during a transition window; new
  verification uses the new chain. This is the standard technique real CAs
  use for a root rollover without a "flag day" where every relying party
  must update simultaneously.
- **Re-issue the intermediate fresh under the new root**, and treat this
  identically to §4.1 (revoke, re-issue every leaf, repoint the service).
  Simpler, but loses continuity: nothing chains through the old root any
  more, so any relying party that only trusts the old root is locked out
  until it updates.

Cross-signing is **not implemented** in this repository — `RunCeremony`
signs one intermediate under the root key pair it just generated in the
same run; there is no path that takes an *existing* intermediate public key
and signs it under a *newly generated* root. It is recorded here as
documented-design (CLAUDE.md §2.3): the mechanism is ordinary
`x509.CreateCertificate` with an existing public key and a new issuer,
identical in shape to what `signRootAndIntermediate` already does for the
first-ever intermediate, but no operator-facing command exists to invoke it
against a *pre-existing* key. Building it is future work, not scoped to any
phase file yet.

### 4.3 Losing both tokens

No cross-signing is possible — there is no existing intermediate key left
to sign. This is a full restart: a fresh two-tier ceremony, a new trust
anchor distributed to every relying party out of band, and every
certificate ever issued under the old hierarchy re-issued from scratch.
There is no shortcut, and none should be invented — a CA's trust anchor
being unrecoverable except by starting over is not a defect in the design,
it is what "the root is the root" means.

## 5. Wrap-based backup design

### 5.1 The mechanism

PKCS#11's `C_WrapKey` / `C_UnwrapKey` pair (Phase 1's `Wrap`/`Unwrap` on
`VendorAdapter`) lets one HSM-held key export another **only in encrypted
form**, and only if the exported key's `CKA_EXTRACTABLE` is `true`. The
plaintext key material never enters application memory at any point — it is
encrypted inside the token and decrypted inside a token (the same one, or a
different one) that holds the matching unwrapping key. That is the entire
value proposition: a backup that is useless without also holding the
wrapping key, which is itself an HSM-held object, ordinarily kept under
separate custody from the key it protects.

`internal/pkcs11`'s
`TestConformance/WrapUnwrapDemo_ECPrivateKeyBackupRoundTrip` proves the
mechanics: generate an EC key pair with `Extractable: true`, sign with it,
wrap its private key under an AES wrapping key, **destroy the original
object** (simulating the token it lived on being lost), unwrap the ciphertext
back into a new object, and sign again — the second signature verifies
against the same public key the first one did. It runs on both backends per
CLAUDE.md §2.4 and is the sub-task's optional demo, built because
`DestroyObject` (3b.8) made the "simulate loss" step possible.

**What this is not**: a working restore procedure by itself. It proves the
primitive round-trips on one token; a real backup unwraps onto a
*different* token under separate custody, which `C_UnwrapKey` does not
care about (it is symmetric in which token performs which half) but which
this repository's test harness has no third token to actually exercise.

### 5.2 Deciding root-key extractability

`CKA_EXTRACTABLE=false` — this platform's default for every key it
generates, including the root (`internal/pkcs11/types.go`,
`KeyPairRequest.Extractable`'s doc comment) — and a wrap-based backup of
that same key are mutually exclusive. A non-extractable key has no door
`C_WrapKey` can use. So the root ceremony faces a genuine fork with no
default that is obviously correct for every deployment:

- **Non-extractable root.** Matches every other key on this platform, and
  the strongest reading of CLAUDE.md §3.1. No wrap-based backup exists for
  the root; losing the token means §4.2 or §4.3, unconditionally.
- **Extractable root.** A wrapped backup becomes possible, at a real cost:
  `CKA_EXTRACTABLE=true` does not distinguish a legitimate backup operator
  from `threat-model.md`'s A7 (a malicious ceremony operator) or a
  successful A6 token attack — either can wrap the key out under a
  wrapping key of their own choosing, during the same session that has the
  root authenticated anyway. The wrapped bytes stay meaningfully protected
  only if the wrapping key is under *separate* custody the same attacker
  does not also control — a second HSM, ideally under quorum, which is
  exactly what §6's vendor-native mechanisms provide and this repository's
  own AES-wrap demo, run on one token, does not.

**Decided 2026-08-31 by the maintainer:** neither hard-coded default.
Asked at ceremony time, as an explicit per-run operator choice —
`CeremonyParams.RootKeyExtractable` and `hsm-pki-keytool ceremony`'s
`-root-key-extractable` flag — **defaulting to `true`**. The reasoning for
defaulting on rather than off: a disposable development token has nothing
worth restoring, so an off-by-default would make the case that actually
matters — a real root, meant to last years — the one an operator has to
remember to opt into, at exactly the one moment (ceremony time) that choice
can ever be made. `TestRunCeremony_RootKeyExtractableIsOperatorControlled`
proves the flag reaches the token's `CKA_EXTRACTABLE` attribute in both
directions, read back rather than assumed from the request (CLAUDE.md
§3.10), on both backends. The choice is echoed in the ceremony's own
output (§2.3) so it becomes part of that run's record rather than a fact
an operator has to separately remember.

This does not weaken `CKA_SENSITIVE`, which `GenerateKeyPair` forces `true`
unconditionally regardless of `Extractable` (3b.7) — `C_GetAttributeValue`
still refuses to disclose the key in the clear either way.
`CKA_EXTRACTABLE` and `CKA_SENSITIVE` govern two different doors
(`docs/pkcs11-vendor-notes.md`, "A non-sensitive private key really is
readable here"), and only the wrap door is ever opened by this decision.

### 5.3 Verify after restore — a measured requirement, not a suggestion

Building the demo in §5.1 found a real divergence, not a hypothetical one:
restoring a key via `C_UnwrapKey` does **not** guarantee the restored
object actually carries the restrictive attributes the unwrap template
asked for.

| Backend | Restored private key's `CKA_EXTRACTABLE`, template asked for `false` |
|---|---|
| SoftHSM2 2.6.1 | `false` — the template is honored |
| ProtectToolkit 7.3.3 | **`true`** — the template's request is silently ignored |

Both are conformant (`docs/pkcs11-vendor-notes.md`, "A restored key does
not necessarily inherit the restrictive attributes you asked for"). This is
the same class of finding as 3b.7's `CKA_SENSITIVE` disclosure — a
caller-requested restriction the standard does not obligate any vendor to
honor — and it cannot be closed the same way that one was: `GenerateKeyPair`
could force `CKA_SENSITIVE=true` unconditionally because no legitimate
caller anywhere in this platform wants a readable private key, but `Unwrap`
is a generic primitive with legitimately different needs per call (the
AES payload-key round trip in the same conformance suite needs
`Extractable: true` to survive the restore), so there is no single default
this platform's own code can force.

**The operational rule this produces:** after restoring any key from a
wrapped backup, on any vendor, read its attributes back off the token and
confirm them before trusting the restored key with anything — never trust
the template that was sent. This is CLAUDE.md §3.10's "ask the token, not
the request" discipline, applied to a restore instead of a generation.

### 5.4 What this must never be used for

The wrapping key's purpose is narrow, and widening it is exactly the
mistake this section exists to head off:

- **Never a bulk-export key.** A wrapping key that can wrap *any* object on
  the token is a single point of failure that recreates the disclosure
  risk §3.1 exists to prevent, just moved one layer over — compromise the
  wrapping key and every extractable private key on the token is
  recoverable. Scope it (`CKA_WRAP` / `CKA_UNWRAP` set only on the
  purpose-built wrapping key, used only for the specific backup-eligible
  key it exists to protect) rather than treating it as a general escape
  hatch.
- **Never a transport mechanism to an untrusted token.** Unwrapping a key
  onto a token this platform does not control is indistinguishable, from
  the source token's perspective, from handing the plaintext to whoever
  controls that token — the ciphertext's confidentiality is entirely a
  function of who holds the unwrapping key.
- **Never a substitute for §5.3's verification step.** A backup that
  restores into an unexpectedly extractable key (as measured on
  ProtectToolkit above) has quietly widened the very door it existed to
  guard, unless someone checks.

## 6. Vendor-native mechanisms (documented-design)

**Labelled per CLAUDE.md §2.3: none of this has been run.** What follows is
what each vendor's published documentation states its own mechanism
provides — not a claim this repository has exercised, verified, or can
currently afford the hardware/licensing to exercise. Where this repository
*has* measured vendor behavior directly, it is in
`docs/pkcs11-vendor-notes.md`, not here.

- **nShield Security World / ACS quorum (Thales, Phase 7).** A Security
  World defines an Administrator Card Set (ACS) with a configurable
  quorum (`K` of `N` cards required). Keys are protected by the Security
  World rather than by a single token, and can be backed up as an
  encrypted archive restorable onto replacement hardware belonging to the
  same Security World. The quorum is the separation-of-duties mechanism
  this repository's own single-operator ceremony (§7's non-goal in
  `threat-model.md`) explicitly does not provide.
- **Luna cloning domains (Thales/SafeNet, Phase 7).** Partitions in the
  same cloning domain can clone key material directly between HSMs sharing
  that domain, authenticated by a domain identifier known only to
  authorized partitions — a different mechanism from PKCS#11's
  `Wrap`/`Unwrap` (domain membership rather than a wrapping key object),
  used for the same purpose: moving key material between physically
  separate HSMs without it ever existing in the clear outside a token.
- **ProtectServer backup (Thales ProtectToolkit).** ProtectToolkit provides
  vendor tooling (`ctbackup`/`ctrestore`-class utilities) to back up and
  restore token contents, typically split-knowledge, multi-custodian
  procedures for the SO/backup credentials involved — a different surface
  again from the PKCS#11-level `Wrap`/`Unwrap` this repository exercises
  directly in §5.

All three exist specifically to solve the separation-of-custody problem
§5.2 identifies with a bare AES wrapping key on one token: the backup
credential and the operational credential are different people, different
cards, or different domains, so no single compromised session can both
create and exfiltrate a usable copy of the key.

## 7. CA-key rotation design (documented-design)

CLAUDE.md §3.7 states the rule this section designs for: every signing key
has a lifecycle, and the CA hierarchy rotates by "re-issuing the
intermediate (routine) or by root roll-over with cross-signing (exceptional,
ceremony-governed)". Mechanically, both are exactly §4.1 and §4.2 above —
rotation and disaster recovery are the same two procedures, run
electively instead of in response to loss. Restated briefly, for the
rotation framing specifically:

- **Intermediate re-issue (routine).** A new intermediate key pair, signed
  under the *existing, unchanged* root, on a schedule the operator picks —
  not in response to any incident. Blocked today on the same gap §4.1.1
  names: no code path signs a fresh intermediate under an existing root
  without also regenerating the root.
- **Root roll-over with cross-signing (exceptional).** A new root, with the
  *existing* intermediate cross-signed under it during a transition
  window so relying parties are not forced to update atomically. Blocked
  today on the gap §4.2 names: no code path signs an existing intermediate
  public key under a newly generated root.

Neither gap is scoped to a phase file yet; both are natural extensions of
the `hsm-pki-keytool` work Phase 4.8 already does for the image/artifact
signing keys; §4.1.1 and this section are the record that they are needed,
for whoever picks them up. The *signing keys'* (image, artifact) own
rotation — distinct from the CA hierarchy this section covers — is
implemented in Phases 4.8 and 5.9 per CLAUDE.md §3.7, with a mechanical
rotation drill in CI (`docs/phases/phase-5-cicd.md`, 5.9).

## 8. Cross-references

- Threat model — what each key is worth, what each attacker gets:
  [`threat-model.md`](threat-model.md)
- Blast-radius reasoning behind the two-tier hierarchy:
  [`architecture.md`](architecture.md), "Two-tier hierarchy rather than a
  single online CA"
- Vendor behavior actually measured, not merely claimed:
  [`pkcs11-vendor-notes.md`](pkcs11-vendor-notes.md)
- ProtectServer token provisioning and the two-token setup:
  [`protectserver-setup.md`](protectserver-setup.md) §3b, §3c
- The ceremony as built: `internal/ca/ceremony.go`,
  `cmd/hsm-pki-keytool/main.go`, and
  [`phases/phase-3b-pki-hardening.md`](phases/phase-3b-pki-hardening.md)
  sub-task 3b.1
- Signing-key (not CA-hierarchy) rotation and the CI rotation drill:
  [`phases/phase-4-container-k8s.md`](phases/phase-4-container-k8s.md) 4.8,
  [`phases/phase-5-cicd.md`](phases/phase-5-cicd.md) 5.9
