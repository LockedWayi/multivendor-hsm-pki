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

// ReissueIntermediateParams configures ReissueIntermediate. It is
// CeremonyParams without the root's generation fields, and it stays a
// separate type. A flag that switches between "generate a root" and "never
// generate a root" would put the most destructive operation in this
// repository one wrong argument away from a routine one. No field here can
// cause a root key to be created.
type ReissueIntermediateParams struct {
	// RootWorkspace and RootPIN reach the offline root token. Only the
	// ceremony and this operation log into it, and both are operator-run.
	RootWorkspace pk11.Workspace
	RootPIN       PINResolver
	// RootKeyLabel names the existing root key. A missing key is
	// ErrKeyNotFound. This never creates one.
	RootKeyLabel string
	// RootCurve is the curve the existing root key was generated on.
	RootCurve pk11.ECCurve
	// RootCert is the existing root certificate from the original ceremony.
	// It is required: the root's certificate is not stored on the token,
	// and a reconstructed template would not match the root relying parties
	// already trust.
	RootCert *x509.Certificate

	IntermediateWorkspace pk11.Workspace
	IntermediatePIN       PINResolver
	// IntermediateKeyLabel is the new key label, the next version. It must
	// be free. The old intermediate keeps working through its transition
	// window.
	IntermediateKeyLabel string
	IntermediateSubject  pkix.Name
	IntermediateCurve    pk11.ECCurve
	// IntermediateValidity defaults to DefaultIntermediateValidity when zero.
	IntermediateValidity time.Duration

	// RootCRLURL and RootCertURL are fixed at signature time, as in
	// CeremonyParams.
	RootCRLURL  string
	RootCertURL string
}

// ReissueIntermediateResult carries the new intermediate certificate, DER,
// public material only. There is no root CRL: re-issuing does not revoke
// the previous intermediate. Revoking it is a separate decision at the end
// of the transition window.
type ReissueIntermediateResult struct {
	IntermediateCertDER []byte
}

// validate checks everything checkable without touching a token, before
// any key is generated. A mistake caught after the new key exists costs a
// manual cleanup on the token.
func (p *ReissueIntermediateParams) validate() error {
	if p.RootWorkspace.Serial == "" || p.IntermediateWorkspace.Serial == "" {
		return fmt.Errorf("ca: reissue-intermediate requires both workspaces to carry a token serial number; got root=%q intermediate=%q; a Workspace built by hand rather than returned by Workspaces() will not have one",
			p.RootWorkspace.Serial, p.IntermediateWorkspace.Serial)
	}
	// The serial identifies a token.
	if p.RootWorkspace.Serial == p.IntermediateWorkspace.Serial {
		return fmt.Errorf("ca: reissue-intermediate refuses to run with root and intermediate on the same token (serial %q, labels %q and %q); the root must be on its own token",
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
	// The same emptiness test validateCSR applies to a leaf, checked before
	// the first key exists.
	if p.IntermediateSubject.CommonName == "" && len(p.IntermediateSubject.Organization) == 0 {
		return fmt.Errorf("%w: reissue-intermediate needs an intermediate subject carrying at least a common name or an organization",
			ErrEmptySubject)
	}
	// Early rejection. The authoritative check runs again at the point of
	// signature; see checkRootMaySign.
	return checkRootMaySign(p.RootCert, p.IntermediateValidity, time.Now())
}

// checkRootMaySign checks that the root may sign an intermediate with the
// requested validity at time now: it is a CA certificate, asserts
// keyCertSign, is self-signed, is not constrained to pathlen:0, is inside
// its validity window, and outlives the new intermediate.
//
// It runs twice: in validate, before any key exists, and again at the
// moment the template is built. Key generation, a token login and an
// object search happen in between, and the lifetime approved must be
// measured from the instant the certificate carries. An earlier version
// measured it from validate time only. checkIssuerCanCover does the same
// at leaf issuance.
func checkRootMaySign(root *x509.Certificate, interValidity time.Duration, now time.Time) error {
	if !root.BasicConstraintsValid {
		return fmt.Errorf("%w: the supplied root certificate carries no basicConstraints extension, so it asserts no CA status at all (RFC 5280 §4.2.1.9)",
			ErrNotAnIntermediate)
	}
	if !root.IsCA {
		return fmt.Errorf("%w: the supplied root certificate is not a CA certificate (IsCA=false)", ErrNotAnIntermediate)
	}
	// RFC 5280 §4.2.1.3.
	if root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: the supplied root certificate does not assert the keyCertSign key usage, so the intermediate it signs would be rejected by a compliant verifier (RFC 5280 §4.2.1.3)",
			ErrNotAnIntermediate)
	}
	// Checked by verifying the signature, not by comparing Subject to
	// Issuer. It runs after the IsCA and keyCertSign checks:
	// CheckSignatureFrom refuses when the parent lacks CA status or
	// keyCertSign, and would report a genuine root as not self-signed.
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("ca: the supplied root certificate is not self-signed, so it is not the root of this hierarchy: %w", err)
	}
	// A root with pathlen:0 may certify no CA below it. MaxPathLenZero
	// alone is the test: an unconstrained certificate parses as MaxPathLen
	// -1 and MaxPathLenZero false, an explicit pathlen:0 as 0 and true.
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
	// Refused, not clamped, for the same reason as in the ceremony. The
	// zero default is kept: a zero duration makes now.Add(interValidity)
	// equal now, which is inside any unexpired root, so a caller reaching
	// this function with an un-normalized value would pass the one check
	// it is here for.
	if interValidity == 0 {
		interValidity = DefaultIntermediateValidity
	}
	if expiry := now.Add(interValidity); expiry.After(root.NotAfter) {
		return fmt.Errorf("%w: the new intermediate would expire at %s, after the root's own %s; re-issue for a shorter validity, or roll the root over with cross-signing (docs/key-ceremony-and-recovery.md)",
			ErrValidityExceedsIssuer, expiry.Format(time.RFC3339), root.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// ReissueIntermediate signs a new intermediate certificate, over a new
// intermediate key pair, under the existing offline root. This is the
// routine rotation. The sequence is the ceremony's minus root generation:
// generate the new intermediate key pair on its token, log into the root
// token, confirm the two tokens are separate, find the existing root key,
// sign.
//
// A missing root key is a hard error. A rotation that generated a root on
// a typo in RootKeyLabel would produce an intermediate that verifies
// against a root nobody trusts, and the failure would appear at every
// relying party at once.
//
// A non-nil result can come back with a non-nil error, as with
// RunCeremony: the new key label is taken by then and the certificate
// cannot be regenerated. Callers persist it and then report the error.
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
		// A serial is a claim the driver makes; an object search is a
		// measurement. If the key generated a moment ago on the
		// intermediate token is visible from this session, the two
		// workspaces are one key space.
		interVisibleFromRoot, err := keyPairExists(ctx, adapter, params.RootWorkspace, sessionOpts, params.IntermediateKeyLabel)
		if err != nil {
			return nil, fmt.Errorf("ca: reissue-intermediate: checking token separation: %w", err)
		}
		if interVisibleFromRoot {
			return nil, fmt.Errorf("ca: reissue-intermediate aborted: the new intermediate key label %q is visible from the root token (label %q, serial %q), so these are the same key space despite reporting different serials; the root must be on its own token",
				params.IntermediateKeyLabel, params.RootWorkspace.Label, params.RootWorkspace.Serial)
		}
		return signIntermediateUnderExistingRoot(ctx, adapter, sessionOpts, params, interPub)
	})
}

// signIntermediateUnderExistingRoot runs with the root token
// authenticated.
func signIntermediateUnderExistingRoot(ctx context.Context, adapter pk11.VendorAdapter, sessionOpts pk11.SessionOptions, params ReissueIntermediateParams, interPub *ecdsa.PublicKey) (*ReissueIntermediateResult, error) {
	// Fail closed when the root key is absent. See ReissueIntermediate.
	exists, err := keyPairExists(ctx, adapter, params.RootWorkspace, sessionOpts, params.RootKeyLabel)
	if err != nil {
		return nil, fmt.Errorf("ca: reissue-intermediate: looking for the root key: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("%w: no root key labeled %q on token %q (serial %q); reissue-intermediate signs under an existing root and never creates one; check the label, or run a ceremony if this hierarchy does not exist yet",
			ErrKeyNotFound, params.RootKeyLabel, params.RootWorkspace.Label, params.RootWorkspace.Serial)
	}

	rootSigner, err := NewSigner(ctx, adapter, params.RootWorkspace, sessionOpts, params.RootKeyLabel, params.RootCurve)
	if err != nil {
		return nil, fmt.Errorf("ca: reissue-intermediate: opening the root signer: %w", err)
	}
	// The label addressed a key. This confirms it is the key the root
	// certificate certifies.
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

	// The authoritative check, at the instant the certificate will carry.
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
		// The same constraint the ceremony sets. A re-issued intermediate is
		// the same kind of object as the one it succeeds.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		SubjectKeyId:   interSKI,
		// The root's SKI comes from its certificate, not recomputed, so the
		// path relying parties already build is unchanged.
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
