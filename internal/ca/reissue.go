package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// ReissueIntermediateParams configures ReissueIntermediate.
//
// It looks like CeremonyParams with the root's generation fields removed,
// and that is exactly what it is — but the removal is the whole point, so
// the two types stay separate rather than one growing a "reuse the existing
// root" flag. A boolean that switches between "generate a root" and "never
// generate a root" puts the most destructive operation in this repository
// one wrong argument away from a routine one. There is no field here that
// can cause a root key to be created, which is a property a reader can
// check by reading the struct.
//
// Note what is also absent: no RootValidity, no RootCRLValidity, no
// RootSubject, no RootCurve. The root already exists; its certificate is an
// input to be read, not a thing to be described.
type ReissueIntermediateParams struct {
	// RootWorkspace and RootPIN reach the offline root token. This is the
	// only operation besides the ceremony that logs into it, and like the
	// ceremony it is operator-run: nothing the online service ships can
	// name this token.
	RootWorkspace pk11.Workspace
	RootPIN       PINResolver
	// RootKeyLabel names the EXISTING root key. ReissueIntermediate fails
	// closed if no key carries this label — it never creates one, which is
	// what separates a routine rotation from a new hierarchy.
	RootKeyLabel string
	// RootCurve is the curve the existing root key was generated on, needed
	// to open a signer over it. A mismatch surfaces as a key/certificate
	// mismatch rather than a bad signature, because RootCert is checked
	// against the key this names.
	RootCurve pk11.ECCurve
	// RootCert is the existing root certificate, the one an operator kept
	// from the original ceremony. It is required rather than re-derivable:
	// the root's certificate is not stored on the token, and signing under
	// a reconstructed template would produce an intermediate whose issuer
	// fields do not match the root relying parties already trust.
	RootCert *x509.Certificate

	IntermediateWorkspace pk11.Workspace
	IntermediatePIN       PINResolver
	// IntermediateKeyLabel is the NEW key label — the next version, per
	// the key lifecycle's versioned-label rule. It must be free: rotation
	// provisions the next version alongside the previous one, so that the
	// old intermediate keeps working through its transition window. A
	// rotation that overwrote the label in place would revoke nothing and
	// break everything holding a certificate under the old key.
	IntermediateKeyLabel string
	IntermediateSubject  pkix.Name
	IntermediateCurve    pk11.ECCurve
	// IntermediateValidity defaults to DefaultIntermediateValidity when zero.
	IntermediateValidity time.Duration

	// RootCRLURL and RootCertURL are required for the same irreversibility
	// reason as in CeremonyParams: they are fixed at signature time and the
	// root goes back offline afterwards.
	RootCRLURL  string
	RootCertURL string
}

// ReissueIntermediateResult carries the newly signed intermediate
// certificate. DER only, and public material only — no private key ever
// leaves either token.
//
// There is deliberately no root CRL here. Re-issuing an intermediate does
// not revoke the previous one: the two overlap for a stated transition
// window, and revoking the old intermediate is a separate,
// explicit decision made at the end of that window rather than a side
// effect of minting its successor.
type ReissueIntermediateResult struct {
	IntermediateCertDER []byte
}

// validate checks everything checkable without touching an HSM, before
// ReissueIntermediate generates any key. A parameter
// mistake caught after the new key pair exists costs the operator a manual
// cleanup on the token, because the label is then taken and the next
// attempt is refused by the overwrite guard.
func (p *ReissueIntermediateParams) validate() error {
	if p.RootWorkspace.Serial == "" || p.IntermediateWorkspace.Serial == "" {
		return fmt.Errorf("ca: reissue-intermediate requires both workspaces to carry a token serial number; got root=%q intermediate=%q — a Workspace built by hand rather than returned by Workspaces() will not have one",
			p.RootWorkspace.Serial, p.IntermediateWorkspace.Serial)
	}
	// Serial, not label and not slot ID, is what identifies a token
	//
	if p.RootWorkspace.Serial == p.IntermediateWorkspace.Serial {
		return fmt.Errorf("ca: reissue-intermediate refuses to run with root and intermediate on the same token (serial %q, labels %q and %q) — the root's isolation is the property this operation must not spend",
			p.RootWorkspace.Serial, p.RootWorkspace.Label, p.IntermediateWorkspace.Label)
	}
	if p.RootKeyLabel == "" || p.IntermediateKeyLabel == "" {
		return fmt.Errorf("ca: reissue-intermediate requires both key labels to be set")
	}
	if p.RootKeyLabel == p.IntermediateKeyLabel {
		return fmt.Errorf("ca: reissue-intermediate refuses to use one key label (%q) for both tiers", p.RootKeyLabel)
	}
	if err := ValidateDistributionURL("RootCRLURL", p.RootCRLURL); err != nil {
		return fmt.Errorf("ca: reissue-intermediate: %w (ReissueIntermediateParams documents why this is required)", err)
	}
	if err := ValidateDistributionURL("RootCertURL", p.RootCertURL); err != nil {
		return fmt.Errorf("ca: reissue-intermediate: %w (ReissueIntermediateParams documents why this is required)", err)
	}
	if p.RootCert == nil {
		return fmt.Errorf("ca: reissue-intermediate requires the existing root certificate")
	}
	// The same emptiness test validateCSR applies to a leaf's subject, for
	// the same reason and with more at stake: this one names a CA. An empty
	// subject is checkable without touching the HSM, so it is rejected
	// before the first key exists rather than after — the
	// alternative is an operator discovering it from `openssl x509 -text`
	// with the new label already taken.
	if p.IntermediateSubject.CommonName == "" && len(p.IntermediateSubject.Organization) == 0 {
		return fmt.Errorf("%w: reissue-intermediate needs an intermediate subject carrying at least a common name or an organization",
			ErrEmptySubject)
	}
	// Early rejection only. The authoritative check runs again at the point
	// of signature — see checkRootMaySign's doc comment for why one is not
	// enough.
	return checkRootMaySign(p.RootCert, p.IntermediateValidity, time.Now())
}

// checkRootMaySign is the issuer-authority rule applied to the offline root: before
// signing, the CA checks that *it* may sign. The failure this prevents is
// the expensive kind — the intermediate is produced successfully and its
// defect surfaces at a relying party, months later, by which time the root
// is back in its safe and the certificates under the new intermediate are
// already deployed.
//
// # Why now is a parameter, and why this runs twice
//
// the issuer-authority rule is explicit that startup validation does not discharge the check:
// it belongs at the point of use as well. Here "startup" is validate(),
// which runs before any key exists, and "point of use" is the moment the
// certificate template is built. They are not the same instant — an HSM key
// generation, a token login and an object search happen in between, and on
// hardware that is not instant.
//
// Taking the time as a parameter is what makes the second call meaningful.
// An earlier version computed time.Now() internally and was only called
// from validate(), so the lifetime it approved was measured from a moment
// strictly before the one the certificate ends up carrying: the template's
// NotAfter is signing-time now plus the validity, while the approval said
// validate-time now plus the validity fits inside the root. The difference
// is small, and it is exactly the wrong thing to leave to chance on a
// certificate the offline root signs once — a root within seconds of the
// boundary would hand back an intermediate that outlives it, which is the
// case the issuer-authority rule exists to prevent and the one no relying party forgives.
//
// ca.checkIssuerCanCover makes the same call at leaf issuance, for the same
// reason, and this is that pattern applied one tier up.
func checkRootMaySign(root *x509.Certificate, interValidity time.Duration, now time.Time) error {
	if !root.BasicConstraintsValid {
		return fmt.Errorf("%w: the supplied root certificate carries no basicConstraints extension, so it asserts no CA status at all (RFC 5280 §4.2.1.9)",
			ErrNotAnIntermediate)
	}
	if !root.IsCA {
		return fmt.Errorf("%w: the supplied root certificate is not a CA certificate (IsCA=false)", ErrNotAnIntermediate)
	}
	// keyCertSign is what a compliant verifier enforces (RFC 5280
	// §4.2.1.3). Without it every intermediate signed here is rejected by
	// every such verifier, and this operation exists to produce one.
	if root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: the supplied root certificate does not assert the keyCertSign key usage, so the intermediate it signs would be rejected by a compliant verifier (RFC 5280 §4.2.1.3)",
			ErrNotAnIntermediate)
	}
	// A root is self-signed by definition, and this is checked by
	// verifying the signature rather than by comparing Subject to Issuer:
	// those strings are operator-controlled and say nothing about who
	// actually signed it (the same reasoning as checkIntermediateCert's,
	// inverted — there a self-signed certificate is the error).
	//
	// This runs AFTER the IsCA and keyCertSign checks above, and the order
	// is deliberate rather than incidental. CheckSignatureFrom refuses
	// outright when the parent lacks CA status or keyCertSign — "parent
	// certificate cannot sign this kind of certificate" — so with the
	// checks the other way round, a root that is genuinely self-signed but
	// missing keyCertSign was reported as "not self-signed". That is a
	// misleading diagnostic to hand an operator who has an offline root
	// out of its safe, which is the least convenient moment to be told the
	// wrong thing about it.
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("ca: the supplied root certificate is not self-signed, so it is not the root of this hierarchy: %w", err)
	}
	// pathlen on the root bounds how many CAs may appear below it. A root
	// with pathlen:0 may certify end entities but no further CA, so the
	// intermediate about to be signed would be unusable as a CA — which is
	// the only thing it is for.
	//
	// MaxPathLenZero is the whole test, and MaxPathLen must not be added to
	// it. Measured against this Go version rather than assumed: a
	// certificate carrying no pathLenConstraint parses as MaxPathLen = -1,
	// MaxPathLenZero = false; an explicit pathlen:0 parses as 0/true; an
	// explicit pathlen:1 as 1/false. So MaxPathLenZero distinguishes
	// "constrained to zero" from "unconstrained" on its own, and a check
	// that also tested MaxPathLen == 0 would either be dead or would reject
	// the unconstrained root it is meant to accept.
	if root.MaxPathLenZero {
		return fmt.Errorf("%w: the supplied root certificate carries pathlen:0, so no CA may be certified beneath it and the intermediate this would produce could sign nothing",
			ErrNotAnIntermediate)
	}
	if now.Before(root.NotBefore) {
		return fmt.Errorf("%w: the supplied root certificate is not valid until %s", ErrIssuerNotValid, root.NotBefore.Format(time.RFC3339))
	}
	if now.After(root.NotAfter) {
		return fmt.Errorf("%w: the supplied root certificate expired at %s", ErrIssuerNotValid, root.NotAfter.Format(time.RFC3339))
	}
	// The issuer must be able to cover the lifetime about to be granted.
	// Rejected rather than silently clamped, for the same reason the
	// ceremony rejects it: clamping hands the operator a certificate whose
	// lifetime differs from the one they asked for, discovered long after
	// the offline root went back into storage.
	//
	// The zero-default looks redundant, because ReissueIntermediate applies
	// the same one before validate() ever runs. It is kept because dropping
	// it makes the check below *weaker* rather than merely shorter: a zero
	// duration turns now.Add(interValidity) into now, which is inside any
	// unexpired root, so a caller reaching this function directly with an
	// un-normalized value would silently receive a pass on the one question
	// it is here to ask. A guard that only fires for a caller who made a
	// mistake is still the guard doing its job.
	if interValidity == 0 {
		interValidity = DefaultIntermediateValidity
	}
	if expiry := now.Add(interValidity); expiry.After(root.NotAfter) {
		return fmt.Errorf("%w: the new intermediate would expire at %s, after the root's own %s — re-issue for a shorter validity, or roll the root over with cross-signing (docs/key-ceremony-and-recovery.md)",
			ErrValidityExceedsIssuer, expiry.Format(time.RFC3339), root.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// ReissueIntermediate signs a fresh intermediate certificate, over a NEW
// intermediate key pair, under the EXISTING offline root — the routine
// rotation the key lifecycle promises ("the CA hierarchy rotates by re-issuing
// the intermediate (routine)"). Until this existed, that sentence described
// no code path: RunCeremony always generates both tiers in one run, so the
// only way to obtain a new intermediate was to mint a new root, which is
// the exceptional case and rebuilds every trust store that holds it.
//
// The sequence mirrors RunCeremony's, minus the one step that makes a
// ceremony a ceremony: generate the new intermediate key pair on its own
// token, log into the root token, confirm the two tokens really are
// separate, find the existing root key — and stop if it is not there —
// then sign. No root key is ever generated on this path.
//
// # Why the root key is looked up rather than created
//
// The distinction is the entire safety property of this operation. A
// rotation that fell back to generating a root when it could not find one
// would, on a typo in RootKeyLabel, silently produce a second root and an
// intermediate chaining to it. That intermediate verifies perfectly against
// a root nobody trusts, so the failure appears at every relying party at
// once, long after the operator packed the HSM away. Missing root key is
// therefore a hard error.
//
// # Callers must check the result even when the error is non-nil
//
// Same contract as RunCeremony, for the same reason: if the certificate was
// signed and logging out of the root token then failed, the certificate is
// returned alongside the error. The new intermediate key label is taken by
// then, so a second run is refused by the overwrite guard, and discarding
// the certificate would strand a key that can never be certified without
// another root ceremony.
func ReissueIntermediate(ctx context.Context, adapter pk11.VendorAdapter, sessionOpts pk11.SessionOptions, params ReissueIntermediateParams) (*ReissueIntermediateResult, error) {
	if params.IntermediateValidity == 0 {
		params.IntermediateValidity = DefaultIntermediateValidity
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	interPub, err := generateCeremonyKey(ctx, adapter, sessionOpts, params.IntermediateWorkspace, params.IntermediatePIN, params.IntermediateKeyLabel, params.IntermediateCurve)
	if err != nil {
		return nil, fmt.Errorf("ca: reissue-intermediate: new intermediate key: %w", err)
	}

	return withTokenLogin(ctx, adapter, params.RootWorkspace, params.RootPIN, func() (*ReissueIntermediateResult, error) {
		// The same empirical separation check RunCeremony makes, and for
		// the same reason: a serial number is a claim the driver makes, an
		// object search is a fact about the token. If the
		// key generated a moment ago on the "intermediate" token is
		// visible from this session, the two workspaces are one key space
		// however their serials differ — and this operation would be
		// signing with a root that lives beside the key it certifies.
		interVisibleFromRoot, err := keyPairExists(ctx, adapter, params.RootWorkspace, sessionOpts, params.IntermediateKeyLabel)
		if err != nil {
			return nil, fmt.Errorf("ca: reissue-intermediate: checking token separation: %w", err)
		}
		if interVisibleFromRoot {
			return nil, fmt.Errorf("ca: reissue-intermediate aborted: the new intermediate key label %q is visible from the root token (label %q, serial %q), so these are the same key space despite reporting different serials — the root must be isolated (phase-3b-pki-hardening.md)",
				params.IntermediateKeyLabel, params.RootWorkspace.Label, params.RootWorkspace.Serial)
		}
		return signIntermediateUnderExistingRoot(ctx, adapter, sessionOpts, params, interPub)
	})
}

// signIntermediateUnderExistingRoot runs with the root token already
// authenticated (called from inside withTokenLogin by ReissueIntermediate).
func signIntermediateUnderExistingRoot(ctx context.Context, adapter pk11.VendorAdapter, sessionOpts pk11.SessionOptions, params ReissueIntermediateParams, interPub *ecdsa.PublicKey) (*ReissueIntermediateResult, error) {
	// Fail closed when the root key is absent, rather than creating it.
	// See the "Why the root key is looked up rather than created" note on
	// ReissueIntermediate for what this prevents.
	exists, err := keyPairExists(ctx, adapter, params.RootWorkspace, sessionOpts, params.RootKeyLabel)
	if err != nil {
		return nil, fmt.Errorf("ca: reissue-intermediate: looking for the root key: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("%w: no root key labeled %q on token %q (serial %q) — reissue-intermediate signs under an existing root and never creates one; check the label, or run a ceremony if this hierarchy does not exist yet",
			ErrKeyNotFound, params.RootKeyLabel, params.RootWorkspace.Label, params.RootWorkspace.Serial)
	}

	rootSigner, err := NewSigner(ctx, adapter, params.RootWorkspace, sessionOpts, params.RootKeyLabel, params.RootCurve)
	if err != nil {
		return nil, fmt.Errorf("ca: reissue-intermediate: opening the root signer: %w", err)
	}
	// The label addressed a key; this confirms it is *the* key — the one
	// the supplied root certificate attests to. A label is for addressing,
	// not for identity, and signing under a key the root
	// certificate does not certify produces an intermediate that verifies
	// against nothing.
	if err := checkKeyMatchesCert(rootSigner, params.RootCert, params.RootKeyLabel, "the supplied root certificate"); err != nil {
		return nil, fmt.Errorf("ca: reissue-intermediate: %w", err)
	}

	interSKI, err := subjectKeyID(interPub)
	if err != nil {
		return nil, err
	}
	interSerial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	// The authoritative the issuer-authority rule check, against the instant this certificate
	// will actually carry rather than the one validate() saw. Everything
	// between the two — the new key pair, the root login, the separation
	// search — takes time, and the template below is what a relying party
	// ends up holding.
	now := time.Now()
	if err := checkRootMaySign(params.RootCert, params.IntermediateValidity, now); err != nil {
		return nil, fmt.Errorf("ca: reissue-intermediate: the root may no longer sign this: %w", err)
	}

	interTemplate := &x509.Certificate{
		SerialNumber:          interSerial,
		Subject:               params.IntermediateSubject,
		NotBefore:             now.Add(-issuanceClockSkewAllowance),
		NotAfter:              now.Add(params.IntermediateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Explicit pathlen 0, the same constraint the ceremony sets: a
		// re-issued intermediate is the same kind of object as the one it
		// succeeds, and a rotation that quietly widened the hierarchy
		// would be a rotation nobody could review by diffing the two
		// certificates.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		SubjectKeyId:   interSKI,
		// The root's SKI, taken from the certificate rather than
		// recomputed: it is what relying parties already use to build the
		// path to this root, and recomputing it would silently diverge if
		// the original ceremony ever used a different derivation.
		AuthorityKeyId:        params.RootCert.SubjectKeyId,
		CRLDistributionPoints: []string{params.RootCRLURL},
		IssuingCertificateURL: []string{params.RootCertURL},
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, params.RootCert, interPub, rootSigner)
	if err != nil {
		return nil, fmt.Errorf("ca: reissue-intermediate: signing the new intermediate certificate: %w", err)
	}
	return &ReissueIntermediateResult{IntermediateCertDER: interDER}, nil
}
