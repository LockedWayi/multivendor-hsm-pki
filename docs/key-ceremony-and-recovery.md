# Key ceremony and disaster recovery

The companion to [`threat-model.md`](threat-model.md). That document says
what an attacker gets and does not get. This one says what an operator
does: how the root and intermediate come into existence, what record that
leaves, and what to do when a token is lost, stolen, or reaches the end
of its rotation window.

## 1. How to read this

Three audiences, three sections:

- Running the root ceremony for the first time, or refreshing the root
  CRL: §2.
- A token was lost, destroyed, or is suspected compromised: §4.
- Designing what this platform does not yet build. Wrap-based backup,
  vendor-native ceremony hardware, CA rotation: §5 to §7, all labelled
  **documented-design** where they have not been run.

Every artifact this document describes is public: certificates and a CRL.
Nothing here ever writes a private key, a PIN, or a wrapped key blob to a
log line or a plaintext file.

## 2. The root ceremony as an operator procedure

### 2.1 Who, and with what access

One operator, run locally against SoftHSM2 or ProtectToolkit-C software
emulation. This repository demonstrates a **single-operator** ceremony.
§7 of `threat-model.md` states the consequence: it provides no separation
of duties. The operator needs:

- PINs for **two** tokens, the root's and the intermediate's. Never the
  same token. `RunCeremony` refuses to run if the two workspaces resolve
  to the same serial.
- The vendor module path and adapter name (`softhsm2` or `protectserver`).
- Every certificate parameter decided **before** the ceremony starts,
  because a ceremony is irreversible: subject names, the EC curve, and the
  root CRL and root certificate distribution URLs. Those two URLs are
  baked into the intermediate's extensions at signature time and can never
  be changed without bringing the offline root back out to re-sign.
  Validity periods are the one exception. `CeremonyParams` supports
  `RootValidity`, `IntermediateValidity` and `RootCRLValidity`, but
  `hsm-pki-keytool ceremony` does not expose them as flags. Every ceremony
  run through the CLI gets the platform defaults (ten years, five years,
  five years). `CeremonyParams.validate()` still rejects an intermediate
  that would outlive its root at the default values, so this is a missing
  option, not a missing safety check.

`cmd/hsm-pki-keytool`'s `ceremony` subcommand validates every one of these
before it generates the first key (`internal/ca/ceremony.go`,
`CeremonyParams.validate`). A malformed URL or a validity mismatch is
rejected before any key exists on either token.

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

Against ProtectServer, the two tokens are provisioned first with the
ProtectToolkit tools (`ctconf`, `ctkmu`). There is no upgrade path from an
older single-tier token. A single-tier key was never certified by a root,
so it cannot become an intermediate.

### 2.3 What comes out, and what does not

Three files, all PEM, all public:

- The root certificate (`pathlen:1`, self-signed).
- The intermediate certificate (`pathlen:0`, signed by the root), carrying
  the CDP and AIA extensions built from the two URLs above.
- The root's initial CRL, long-lived (`DefaultRootCRLValidity`, five
  years), covering exactly the intermediate, with zero revoked entries. It
  is long-lived because the root stays offline between ceremonies (§2.4).

No private key material of any kind. Both key pairs are generated on, and
never leave, their respective tokens. `RunCeremony` asserts
`adapter.TokenLoggedIn() == false` after it returns, on every path, and
the CLI's success output prints that:

```
no private key material was written anywhere; both key pairs remain on their respective HSM tokens
root private key: CKA_EXTRACTABLE=true; eligible for wrap-based backup (docs/key-ceremony-and-recovery.md)
```

The second line echoes the §5.2 decision. It is printed so it is part of
the ceremony's own record.

**Certificates are written before the error is checked.** If signing
succeeds but the root token's logout then fails, the key pairs already
exist. The ceremony's overwrite guard means a second attempt cannot
recreate them under the same labels, so discarding the certificates at
that point would be unrecoverable. `cmd/hsm-pki-keytool` writes the three
files first and reports the logout error alongside them.

### 2.4 Refreshing the root CRL

The root stays offline between ceremonies, so there is no "publish an
updated root CRL" operation that does not involve the root token.
Refreshing it, whether to extend its validity or to revoke the
intermediate (§4.2), means bringing the root out. §4's disaster recovery
procedures and a routine CRL refresh are the same event mechanically. The
ceremony does not distinguish "the root's CRL is due for renewal" from
"the intermediate was compromised".

## 3. The ceremony manifest

### 3.1 What it is, and why it exists

A key ceremony leaves a written record of what was produced, on which
token, by whom, and when. A later operator uses it to confirm they are
looking at the same token the root was generated on, not one that merely
shares its label. `threat-model.md` §A7 names why this matters: the one
attacker the ceremony's own design cannot stop is the operator running it.
The mitigation is procedural: a written record and, eventually,
multi-person control this repository does not implement (§7 of the threat
model). The manifest is the written half.

### 3.2 Fields

Everything here is public. No PIN, no private key, no wrapped key blob.

| Field | Source | Why it is in the manifest |
|---|---|---|
| Root token label and serial | `pkcs11.Workspace` | Serial is identity, label is address. Both are recorded so a later operator can resolve either |
| Intermediate token label and serial | `pkcs11.Workspace` | Same reasoning, other tier |
| Root key label | operator-supplied flag | What `C_FindObjects` resolves at signing time |
| Intermediate key label | operator-supplied flag | Same, intermediate tier |
| Root key `CKA_EXTRACTABLE` | `-root-key-extractable` | Whether this root is backup-eligible (§5.2). A later operator must not have to re-derive this from the token when deciding whether a restore is possible |
| Root certificate serial number | `CeremonyResult` (parsed) | The value a relying party's chain-building keys on |
| Intermediate certificate serial number | `CeremonyResult` (parsed) | Same, intermediate tier |
| Root and intermediate subject DNs | operator-supplied flags | What the certificates assert, for a human cross-check against what was intended |
| Root and intermediate validity windows | `CeremonyParams` (defaults or flags) | When each certificate, and therefore the chain, stops being valid |
| Root CRL validity | `CeremonyParams` (default or flag) | When the root's CRL must be refreshed |
| Root CRL URL / root certificate URL | operator-supplied flags | The values baked into the intermediate's extensions, irreversibly, at signature time |
| Timestamp | ceremony run time | When this happened, in absolute terms |
| Operator identity | outside this tool's scope | Who ran it. A procedural fact PKCS#11 cannot attest to, recorded by whatever process wraps the ceremony (sign-off sheet, ticket, commit) |

### 3.3 Current state, and what is deferred

Not all of this is captured automatically today. Token labels, key labels,
the CDP and AIA URLs, and the root's `CKA_EXTRACTABLE` choice are either
what the operator typed on the command line or printed by
`hsm-pki-keytool ceremony`'s own stdout. Certificate serial numbers,
subject DNs, and validity windows are **not** printed anywhere. The
operator reads them off the written PEM files (`openssl x509 -text -in
root.pem`, and likewise for the intermediate) and assembles the manifest
by hand from the command line used, the stdout output, and that
inspection. A **structured file**, JSON or YAML, that the ceremony emits
automatically does not exist yet. It is future work.

## 4. Disaster recovery, by tier

"Lost" covers the same set of events regardless of cause: the token is
destroyed, the hardware fails, or a compromise means the key can no longer
be trusted. `threat-model.md` A6 and A7 name the relevant attackers. The
recovery path differs by which tier is lost, and that difference is the
reason this platform has two tiers rather than one.

### 4.1 Losing the intermediate token, the routine case

This is the incident the two-tier hierarchy exists to make cheap. The root
is untouched. Every certificate the root ever signed, including the old
intermediate, is still valid until explicitly revoked. The recovery is:

1. Bring the root out and run `hsm-pki-keytool reissue-intermediate` to
   sign a new intermediate under the existing root key (§4.1.1). Then
   re-run the ceremony's CRL step to publish an updated root CRL revoking
   the old intermediate.
2. Re-issue every leaf that was still validly issued under the old
   intermediate, under the new one. The service cannot do this
   automatically. A leaf's issuer is fixed at signature time, so this is a
   re-issuance campaign.
3. Point the service at the new intermediate certificate and key label
   (`ca.intermediate_cert_path`, `ca.intermediate_key_label`) and restart.
   `ca.LoadIntermediate`'s startup checks refuse to start against anything
   that is not a validly chained, non-self-signed, `pathlen:0` certificate
   whose public key matches the configured key label. A mismatched pairing
   fails at startup rather than issuing certificates nothing can verify.

#### 4.1.1 Routine intermediate rotation

`ca.ReissueIntermediate` (`internal/ca/reissue.go`) and
`hsm-pki-keytool reissue-intermediate` sign a new intermediate under the
**existing** root. The command cannot generate a root at all. A missing
root key is a hard `ErrKeyNotFound`, verified by a test that asserts no
key was created after the failure. This is the procedure for a planned
rotation, or for the loss of the intermediate token alone.

The root still has to come out of storage. It holds the only key that can
sign an intermediate. It is used rather than replaced, so every relying
party keeps the root it already trusts.

```sh
# The root token is attached; the new intermediate key is generated on the
# intermediate's own token, which is never the root's (checked by serial,
# and then confirmed by an object search).
hsm-pki-keytool reissue-intermediate \
  -module "$PKCS11_MODULE" \
  -root-workspace hsm-pki-root -root-pin-env ROOT_PIN \
  -root-key-label ca-root-key-v1 \
  -root-cert /secure/root.pem \
  -root-crl-url  http://pki.example.test/root.crl \
  -root-cert-url http://pki.example.test/root.crt \
  -intermediate-workspace hsm-pki-dev -intermediate-pin-env INTER_PIN \
  -intermediate-key-label ca-intermediate-key-v2 \
  -intermediate-cert-out /secure/intermediate-v2.pem
```

Four things this does not do:

- **It does not generate a root key.** A root key that cannot be found is
  `ErrKeyNotFound`, never a fresh key pair. A typo in `-root-key-label`
  that silently minted a second root would produce an intermediate
  verifying against a root nobody trusts, a failure that appears at every
  relying party at once, long after the HSM went back in the safe.
- **It does not overwrite the previous intermediate's key label.** `-v2`
  is provisioned alongside `-v1`. The old key keeps working, which is what
  makes the next step a transition rather than an outage.
- **It does not revoke the old intermediate.** Overlap is required.
  Revoking is a separate, explicit act at the end of the transition
  window, and it means publishing an updated root CRL, still a root-online
  operation.
- **It does not write private key material anywhere.** Both key pairs
  stay on their tokens.

Then, in order:

1. Point the service at the new certificate and key label
   (`ca.intermediate_cert_path`, `ca.intermediate_key_label`) and restart.
   `ca.LoadIntermediate`'s startup checks refuse a mismatched pairing.
2. Re-issue leaves under the new intermediate over the transition window.
   A leaf's issuer is fixed at signature time, so this is a campaign.
3. At the end of the window, revoke the old intermediate and publish an
   updated root CRL. The root comes out once more for this.
4. Retire the old key by destroying it on the token, per the provision,
   verify-only, retire lifecycle.

Verified on SoftHSM2, 2026-09-05: after a ceremony and a re-issue,
`openssl verify -CAfile root.pem` accepts **both** `intermediate-v1.pem`
and `intermediate-v2.pem`, the two carry different public keys, and the v2
certificate carries `CA:TRUE, pathlen:0` with the root's CDP and AIA. That
has not been run on ProtectToolkit-C software emulation.

### 4.2 Losing the root token, the exceptional case

The root cannot be recovered from a backup unless §5's wrap-based design
was used for it (§5.2, an explicit per-ceremony operator choice). Absent
that, recovery is a **fresh ceremony**: a new root key, on a new or wiped
token, and a decision about the existing intermediate:

- **Cross-sign it.** Have the new root also sign the existing
  intermediate certificate's public key, producing a second intermediate
  certificate (same key, same subject, a different issuer and serial) that
  chains to the new root. Relying parties that already trust the old root
  keep working through the old chain during a transition window. New
  verification uses the new chain. This is the standard technique for a
  root rollover without a flag day where every relying party must update
  simultaneously.
- **Re-issue the intermediate fresh under the new root**, and treat this
  identically to §4.1 (revoke, re-issue every leaf, repoint the service).
  Simpler, and it loses continuity. Nothing chains through the old root
  any more, so any relying party that only trusts the old root is locked
  out until it updates.

Cross-signing is **not implemented** in this repository. `RunCeremony`
signs one intermediate under the root key pair it just generated in the
same run. There is no path that takes an existing intermediate public key
and signs it under a newly generated root. The mechanism is ordinary
`x509.CreateCertificate` with an existing public key and a new issuer,
identical in shape to what `signRootAndIntermediate` does for the
first-ever intermediate, but no operator-facing command exists to invoke
it against a pre-existing key. Building it is future work.

### 4.3 Losing both tokens

No cross-signing is possible. There is no existing intermediate key left
to sign. This is a full restart: a fresh two-tier ceremony, a new trust
anchor distributed to every relying party out of band, and every
certificate ever issued under the old hierarchy re-issued from scratch.
There is no shortcut. A CA's trust anchor being unrecoverable except by
starting over is what "the root is the root" means.

## 5. Wrap-based backup design

### 5.1 The mechanism

PKCS#11's `C_WrapKey` / `C_UnwrapKey` pair (`Wrap` and `Unwrap` on
`VendorAdapter`) lets one HSM-held key export another **only in encrypted
form**, and only if the exported key's `CKA_EXTRACTABLE` is `true`. The
plaintext key material never enters application memory. It is encrypted
inside the token and decrypted inside a token (the same one, or a
different one) that holds the matching unwrapping key. A backup is useless
without also holding the wrapping key, which is itself an HSM-held object,
ordinarily kept under separate custody from the key it protects.

`internal/pkcs11`'s
`TestConformance/WrapUnwrapDemo_ECPrivateKeyBackupRoundTrip` proves the
mechanics: generate an EC key pair with `Extractable: true`, sign with it,
wrap its private key under an AES wrapping key, **destroy the original
object** (simulating the token it lived on being lost), unwrap the
ciphertext back into a new object, and sign again. The second signature
verifies against the same public key the first one did. It runs on both
backends.

**What this is not**: a working restore procedure by itself. It proves the
primitive round-trips on one token. A real backup unwraps onto a different
token under separate custody. `C_UnwrapKey` does not care about that (it
is symmetric in which token performs which half), but this repository's
test harness has no third token to exercise it.

### 5.2 Deciding root-key extractability

`CKA_EXTRACTABLE=false` is this platform's default for every key it
generates, including the root (`internal/pkcs11/types.go`,
`KeyPairRequest.Extractable`). A wrap-based backup of that same key and a
non-extractable key are mutually exclusive. A non-extractable key has no
door `C_WrapKey` can use. The root ceremony faces a fork with no default
that is correct for every deployment:

- **Non-extractable root.** Matches every other key on this platform. No
  wrap-based backup exists for the root. Losing the token means §4.2 or
  §4.3, unconditionally.
- **Extractable root.** A wrapped backup becomes possible, at a cost.
  `CKA_EXTRACTABLE=true` does not distinguish a legitimate backup operator
  from `threat-model.md`'s A7 (a malicious ceremony operator) or a
  successful A6 token attack. Either can wrap the key out under a wrapping
  key of their own choosing, during the same session that has the root
  authenticated. The wrapped bytes stay protected only if the wrapping key
  is under separate custody the same attacker does not also control: a
  second HSM, ideally under quorum, which is what §6's vendor-native
  mechanisms provide and this repository's own AES-wrap demo, run on one
  token, does not.

**Decided 2026-08-31 by the maintainer:** neither hard-coded default. It
is asked at ceremony time, as an explicit per-run operator choice
(`CeremonyParams.RootKeyExtractable` and `hsm-pki-keytool ceremony`'s
`-root-key-extractable` flag), **defaulting to `true`**. A disposable
development token has nothing worth restoring, so an off-by-default would
make the case that matters, a real root meant to last years, the one an
operator has to remember to opt into, at the one moment that choice can be
made. `TestRunCeremony_RootKeyExtractableIsOperatorControlled` proves the
flag reaches the token's `CKA_EXTRACTABLE` attribute in both directions,
read back rather than assumed from the request, on both backends. The
choice is echoed in the ceremony's own output so it becomes part of that
run's record.

This does not weaken `CKA_SENSITIVE`, which `GenerateKeyPair` forces
`true` unconditionally regardless of `Extractable`. `C_GetAttributeValue`
still refuses to disclose the key in the clear either way.
`CKA_EXTRACTABLE` and `CKA_SENSITIVE` govern two different doors, and only
the wrap door is opened by this decision.

### 5.3 Verify after restore, a measured requirement

Building the demo found a divergence. Restoring a key via `C_UnwrapKey`
does **not** guarantee the restored object carries the restrictive
attributes the unwrap template asked for.

| Backend | Restored private key's `CKA_EXTRACTABLE`, template asked for `false` |
|---|---|
| SoftHSM2 2.6.1 | `false`. The template is honored |
| ProtectToolkit-C 7.3.3 software emulation | **`true`**. The template's request is silently ignored |

Both are conformant. This is the same class of finding as the
`CKA_SENSITIVE` disclosure in `test-matrix.md`, a caller-requested
restriction the standard does not obligate any vendor to honor. It cannot
be closed the same way. `GenerateKeyPair` could force `CKA_SENSITIVE=true`
unconditionally because no legitimate caller anywhere in this platform
wants a readable private key. `Unwrap` is a generic primitive with
different needs per call (the AES payload-key round trip in the same
conformance suite needs `Extractable: true` to survive the restore), so
there is no single default this platform's own code can force.

**The operational rule this produces:** after restoring any key from a
wrapped backup, on any vendor, read its attributes back off the token and
confirm them before trusting the restored key with anything. Never trust
the template that was sent.

### 5.4 What this must never be used for

The wrapping key's purpose is narrow:

- **Never a bulk-export key.** A wrapping key that can wrap any object on
  the token is a single point of failure that recreates the disclosure
  risk one layer over. Compromise the wrapping key and every extractable
  private key on the token is recoverable. Scope it: `CKA_WRAP` and
  `CKA_UNWRAP` set only on the purpose-built wrapping key, used only for
  the specific backup-eligible key it exists to protect.
- **Never a transport mechanism to an untrusted token.** Unwrapping a key
  onto a token this platform does not control is indistinguishable, from
  the source token's perspective, from handing the plaintext to whoever
  controls that token. The ciphertext's confidentiality is entirely a
  function of who holds the unwrapping key.
- **Never a substitute for §5.3's verification step.** A backup that
  restores into an unexpectedly extractable key (as measured on
  ProtectToolkit-C above) has widened the door it existed to guard, unless
  someone checks.

## 6. Vendor-native mechanisms (documented-design)

**None of this has been run.** What follows is what each vendor's
published documentation states its own mechanism provides. It is not a
claim this repository has exercised or verified. Where this repository has
measured vendor behaviour directly, it is in
[`test-matrix.md`](test-matrix.md).

- **nShield Security World / ACS quorum (Thales, planned).** A Security
  World defines an Administrator Card Set (ACS) with a configurable quorum
  (`K` of `N` cards required). Keys are protected by the Security World
  rather than by a single token, and can be backed up as an encrypted
  archive restorable onto replacement hardware belonging to the same
  Security World. The quorum is the separation-of-duties mechanism this
  repository's own single-operator ceremony does not provide.
- **Luna cloning domains (Thales/SafeNet, planned).** Partitions in the
  same cloning domain can clone key material directly between HSMs sharing
  that domain, authenticated by a domain identifier known only to
  authorized partitions. That is a different mechanism from PKCS#11's
  `Wrap`/`Unwrap` (domain membership rather than a wrapping key object),
  used for the same purpose: moving key material between physically
  separate HSMs without it ever existing in the clear outside a token.
- **ProtectServer backup (Thales ProtectToolkit).** ProtectToolkit
  provides vendor tooling (`ctbackup`/`ctrestore`-class utilities) to back
  up and restore token contents, typically split-knowledge, multi-custodian
  procedures for the SO and backup credentials involved. That is a
  different surface again from the PKCS#11-level `Wrap`/`Unwrap` this
  repository exercises directly in §5.

All three exist to solve the separation-of-custody problem §5.2 identifies
with a bare AES wrapping key on one token. The backup credential and the
operational credential are different people, different cards, or
different domains, so no single compromised session can both create and
exfiltrate a usable copy of the key.

## 7. CA-key rotation design

Every signing key has a lifecycle. The CA hierarchy rotates by re-issuing
the intermediate (routine) or by root roll-over with cross-signing
(exceptional, ceremony-governed). Mechanically, both are §4.1 and §4.2
above. Rotation and disaster recovery are the same two procedures, run
electively instead of in response to loss.

- **Intermediate re-issue (routine).** A new intermediate key pair, signed
  under the existing, unchanged root, on a schedule the operator picks.
  Implemented: `hsm-pki-keytool reissue-intermediate`, procedure in
  §4.1.1.
- **Root roll-over with cross-signing (exceptional).** A new root, with
  the existing intermediate cross-signed under it during a transition
  window so relying parties are not forced to update atomically. Not
  implemented. No code path signs an existing intermediate public key
  under a newly generated root. It is the harder of the two, because it
  signs a public key that arrives from outside the run rather than one
  just generated, and that is a different trust question from anything
  this codebase does today.

The signing keys (image, artifact) rotate under the same lifecycle, and
their rotation is the shape the CA-hierarchy gaps should take.
`hsm-pki-keytool provision-signing-key` creates the next version under a
new versioned label. It never overwrites one, and it refuses a token that
already holds a CA-hierarchy key. `hsm-pki-keytool generate-inventory -in
<current>` republishes the signed list with the previous version marked
`verify-only`. Retirement is the step that still has no command. The
inventory refuses to call a key retired while its private half is on the
token, so destroying it is a manual `C_DestroyObject`. A rotation drill in
CI is planned, not built.

## 8. Cross-references

- Threat model, what each key is worth and what each attacker gets:
  [`threat-model.md`](threat-model.md)
- Blast-radius reasoning behind the two-tier hierarchy:
  [`architecture.md`](architecture.md), "Two-tier hierarchy rather than a
  single online CA"
- Vendor behaviour measured on both backends:
  [`test-matrix.md`](test-matrix.md), "Expected divergences to look for"
- The ceremony as built: `internal/ca/ceremony.go` and
  `cmd/hsm-pki-keytool/main.go`
- Signing-key (not CA-hierarchy) rotation:
  [`architecture.md`](architecture.md), "The key inventory"
