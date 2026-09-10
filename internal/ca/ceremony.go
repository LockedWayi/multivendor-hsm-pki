package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// DefaultRootValidity is the validity of a ceremony-produced root
// certificate.
const DefaultRootValidity = 10 * 365 * 24 * time.Hour

// DefaultIntermediateValidity is the validity of a ceremony-produced
// intermediate certificate. Shorter than the root's: the intermediate is
// the certificate this platform re-issues.
const DefaultIntermediateValidity = 5 * 365 * 24 * time.Hour

// DefaultRootCRLValidity is the validity of the root's CRL. It is long
// because the root stays offline between ceremonies. Refreshing the CRL
// means running a ceremony.
const DefaultRootCRLValidity = 5 * 365 * 24 * time.Hour

// CeremonyParams configures RunCeremony. Root and intermediate are two
// tokens, never one, so nothing downstream of the ceremony needs to name
// the root's token.
type CeremonyParams struct {
	RootWorkspace pk11.Workspace
	RootPIN       PINResolver
	RootKeyLabel  string
	RootSubject   pkix.Name
	RootCurve     pk11.ECCurve
	// RootValidity defaults to DefaultRootValidity when zero.
	RootValidity time.Duration
	// RootCRLValidity defaults to DefaultRootCRLValidity when zero.
	RootCRLValidity time.Duration

	IntermediateWorkspace pk11.Workspace
	IntermediatePIN       PINResolver
	IntermediateKeyLabel  string
	IntermediateSubject   pkix.Name
	IntermediateCurve     pk11.ECCurve
	// IntermediateValidity defaults to DefaultIntermediateValidity when zero.
	IntermediateValidity time.Duration

	// RootCRLURL becomes the intermediate certificate's CRL distribution
	// point. It is required: the root is offline, so its CRL is the only
	// channel by which a relying party learns the intermediate was revoked,
	// and an extension cannot be added after the signature.
	RootCRLURL string
	// RootCertURL becomes the intermediate's AIA CA-Issuers pointer.
	// Required for the same reason.
	RootCertURL string

	// RootKeyExtractable sets CKA_EXTRACTABLE on the root private key. It
	// is an operator choice per ceremony. true makes a wrap-based backup of
	// the root possible; false leaves a lost root token with no recovery
	// but a fresh ceremony. CKA_SENSITIVE stays true either way. C_WrapKey
	// and C_GetAttributeValue are different doors.
	RootKeyExtractable bool
}

// validate checks every parameter that can be checked without touching a
// token, before RunCeremony generates any key. A ceremony refuses to
// overwrite a label, so a mistake caught after the first key exists costs
// a manual cleanup on the token.
func (p *CeremonyParams) validate() error {
	// The serial identifies a token. Labels are not unique, and a slot ID
	// can change. See pkcs11.Workspace.
	if p.RootWorkspace.Serial == "" || p.IntermediateWorkspace.Serial == "" {
		return fmt.Errorf("ca: ceremony requires both workspaces to carry a token serial number; got root=%q intermediate=%q; a Workspace built by hand rather than returned by Workspaces() will not have one",
			p.RootWorkspace.Serial, p.IntermediateWorkspace.Serial)
	}
	if p.RootWorkspace.Serial == p.IntermediateWorkspace.Serial {
		return fmt.Errorf("ca: ceremony refuses to run with root and intermediate on the same token (serial %q, labels %q and %q); the root must be on its own token",
			p.RootWorkspace.Serial, p.RootWorkspace.Label, p.IntermediateWorkspace.Label)
	}
	if p.RootKeyLabel == "" || p.IntermediateKeyLabel == "" {
		return fmt.Errorf("ca: ceremony requires both key labels to be set")
	}
	if p.RootKeyLabel == p.IntermediateKeyLabel {
		return fmt.Errorf("ca: ceremony refuses to use one key label (%q) for both tiers", p.RootKeyLabel)
	}
	if err := ValidateDistributionURL("RootCRLURL", p.RootCRLURL); err != nil {
		return fmt.Errorf("ca: ceremony: %w (CeremonyParams documents why this is required)", err)
	}
	if err := ValidateDistributionURL("RootCertURL", p.RootCertURL); err != nil {
		return fmt.Errorf("ca: ceremony: %w (CeremonyParams documents why this is required)", err)
	}
	// An intermediate that outlives its root is refused, not clamped. RFC
	// 5280 path validation needs every certificate in the path valid at the
	// time of use, so the chain dies with the root.
	if p.IntermediateValidity > p.RootValidity {
		return fmt.Errorf("ca: intermediate validity (%s) exceeds root validity (%s); the intermediate would outlive the root that signed it",
			p.IntermediateValidity, p.RootValidity)
	}
	return nil
}

// CeremonyResult is the DER of the root certificate, the intermediate
// certificate and the root's initial CRL. No private key material is
// included. Both key pairs stay on their tokens.
type CeremonyResult struct {
	RootCertDER         []byte
	IntermediateCertDER []byte
	RootCRLDER          []byte
}

// RunCeremony bootstraps the two-tier hierarchy: the intermediate's key
// pair on its token, then on the root token the root key pair, a
// self-signed root certificate (pathlen 1), the intermediate certificate
// signed under it (pathlen 0) and the root's initial CRL. It logs out of
// every token it logs into before returning. cmd/hsm-pki-keytool's
// ceremony command is the only caller.
//
// A non-nil *CeremonyResult can come back with a non-nil error, when the
// certificates were signed and the root logout then failed. The key pairs
// exist, a second run is refused, and the certificates exist only in
// memory. Callers persist the result and then report the error.
func RunCeremony(ctx context.Context, adapter pk11.VendorAdapter, sessionOpts pk11.SessionOptions, params CeremonyParams) (*CeremonyResult, error) {
	if params.RootValidity == 0 {
		params.RootValidity = DefaultRootValidity
	}
	if params.RootCRLValidity == 0 {
		params.RootCRLValidity = DefaultRootCRLValidity
	}
	if params.IntermediateValidity == 0 {
		params.IntermediateValidity = DefaultIntermediateValidity
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	interPub, err := generateCeremonyKey(ctx, adapter, sessionOpts, params.IntermediateWorkspace, params.IntermediatePIN, params.IntermediateKeyLabel, params.IntermediateCurve)
	if err != nil {
		return nil, fmt.Errorf("ca: ceremony: intermediate key: %w", err)
	}

	return withTokenLogin(ctx, adapter, params.RootWorkspace, params.RootPIN, func() (*CeremonyResult, error) {
		// A serial is a claim the driver makes; an object search is a
		// measurement. If these two workspaces are one token, the
		// intermediate key generated a moment ago is visible from this
		// session. Checked before the root key exists, so an abort leaves
		// one label used, not two.
		interVisibleFromRoot, err := keyPairExists(ctx, adapter, params.RootWorkspace, sessionOpts, params.IntermediateKeyLabel)
		if err != nil {
			return nil, fmt.Errorf("ca: ceremony: checking token separation: %w", err)
		}
		if interVisibleFromRoot {
			return nil, fmt.Errorf("ca: ceremony aborted: the intermediate key label %q is visible from the root token (label %q, serial %q), so these are the same key space despite reporting different serials; the root must be on its own token",
				params.IntermediateKeyLabel, params.RootWorkspace.Label, params.RootWorkspace.Serial)
		}
		return signRootAndIntermediate(ctx, adapter, sessionOpts, params, interPub)
	})
}

// generateCeremonyKey logs into ws, generates an EC key pair under label,
// and returns its public key. It refuses a label that already exists, and
// logs out on every path.
//
// The existence check and the generation are not atomic. PKCS#11 places no
// uniqueness constraint on CKA_LABEL, so C_GenerateKeyPair creates a second
// pair under a used label and returns success. The use side closes the
// window: findKeyByLabel refuses a label that matches more than one object,
// so a duplicate fails the next signature loudly instead of signing with
// the wrong key.
func generateCeremonyKey(ctx context.Context, adapter pk11.VendorAdapter, sessionOpts pk11.SessionOptions, ws pk11.Workspace, resolvePIN PINResolver, label string, curve pk11.ECCurve) (*ecdsa.PublicKey, error) {
	return withTokenLogin(ctx, adapter, ws, resolvePIN, func() (*ecdsa.PublicKey, error) {
		exists, err := keyPairExists(ctx, adapter, ws, sessionOpts, label)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("ca: ceremony refuses to overwrite existing key label %q on token %q", label, ws.Label)
		}
		if _, err := withSession(ctx, adapter, ws, sessionOpts, func(s *pk11.Session) (struct{}, error) {
			_, err := adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
				Curve: curve, Label: label, Sign: true, Verify: true,
			})
			return struct{}{}, err
		}); err != nil {
			return nil, fmt.Errorf("ca: generating key pair label %q on token %q: %w", label, ws.Label, err)
		}
		signer, err := NewSigner(ctx, adapter, ws, sessionOpts, label, curve)
		if err != nil {
			return nil, err
		}
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("ca: unexpected public key type %T for label %q", signer.Public(), label)
		}
		return pub, nil
	})
}

// signRootAndIntermediate runs with the root token authenticated. It
// generates the root key pair, self-signs the root certificate, signs the
// intermediate certificate over interPub, and builds the root's initial
// CRL.
func signRootAndIntermediate(ctx context.Context, adapter pk11.VendorAdapter, sessionOpts pk11.SessionOptions, params CeremonyParams, interPub *ecdsa.PublicKey) (*CeremonyResult, error) {
	exists, err := keyPairExists(ctx, adapter, params.RootWorkspace, sessionOpts, params.RootKeyLabel)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("ca: ceremony refuses to overwrite existing root key label %q", params.RootKeyLabel)
	}
	if _, err := withSession(ctx, adapter, params.RootWorkspace, sessionOpts, func(s *pk11.Session) (struct{}, error) {
		_, err := adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: params.RootCurve, Label: params.RootKeyLabel, Sign: true, Verify: true,
			Extractable: params.RootKeyExtractable,
		})
		return struct{}{}, err
	}); err != nil {
		return nil, fmt.Errorf("ca: generating root key pair: %w", err)
	}

	rootSigner, err := NewSigner(ctx, adapter, params.RootWorkspace, sessionOpts, params.RootKeyLabel, params.RootCurve)
	if err != nil {
		return nil, err
	}
	rootPub, ok := rootSigner.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ca: unexpected root public key type %T", rootSigner.Public())
	}
	rootSKI, err := subjectKeyID(rootPub)
	if err != nil {
		return nil, err
	}
	rootSerial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               params.RootSubject,
		NotBefore:             now.Add(-issuanceClockSkewAllowance),
		NotAfter:              now.Add(params.RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// The root may certify one level below itself. A standard verifier
		// enforces this, not only this code.
		MaxPathLen:     1,
		SubjectKeyId:   rootSKI,
		AuthorityKeyId: rootSKI,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootSigner)
	if err != nil {
		return nil, fmt.Errorf("ca: self-signing root certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing freshly-signed root certificate: %w", err)
	}

	interSKI, err := subjectKeyID(interPub)
	if err != nil {
		return nil, err
	}
	interSerial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          interSerial,
		Subject:               params.IntermediateSubject,
		NotBefore:             now.Add(-issuanceClockSkewAllowance),
		NotAfter:              now.Add(params.IntermediateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Nothing the intermediate signs may be a CA. MaxPathLenZero must be
		// set with MaxPathLen 0; crypto/x509 treats an unset zero as no
		// constraint.
		MaxPathLen:     0,
		MaxPathLenZero: true,
		SubjectKeyId:   interSKI,
		AuthorityKeyId: rootSKI,
		// The intermediate's revocation status is in the root's CRL. Set
		// now; changing an extension means re-signing with the offline root.
		CRLDistributionPoints: []string{params.RootCRLURL},
		// No OCSP URL: no responder exists.
		IssuingCertificateURL: []string{params.RootCertURL},
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, interPub, rootSigner)
	if err != nil {
		return nil, fmt.Errorf("ca: signing intermediate certificate: %w", err)
	}

	// The root's CRL starts empty. thisUpdate is backdated like the
	// certificates: a relying party with a slow clock would otherwise find
	// no valid CRL, which it cannot tell from "not revoked".
	rootForCRL := &CA{cert: rootCert, signer: rootSigner}
	rootCRLDER, err := rootForCRL.BuildCRL(nil, now.Add(-issuanceClockSkewAllowance), now.Add(params.RootCRLValidity), big.NewInt(1))
	if err != nil {
		return nil, fmt.Errorf("ca: building root CRL: %w", err)
	}

	return &CeremonyResult{
		RootCertDER:         rootDER,
		IntermediateCertDER: interDER,
		RootCRLDER:          rootCRLDER,
	}, nil
}

// keyPairExists reports whether a private key with label exists on the
// token. ErrKeyNotFound means no; any other error is returned.
func keyPairExists(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, label string) (bool, error) {
	return withSession(ctx, adapter, ws, sessionOpts, func(s *pk11.Session) (bool, error) {
		_, err := findKeyByLabel(ctx, adapter, s, pk11.ClassPrivateKey, label)
		if errors.Is(err, ErrKeyNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

// withTokenLogin logs into ws for the span of fn and logs out afterwards,
// on every path, including a panic. It refuses to run when the adapter
// already holds a token authenticated.
//
// A logout failure never discards fn's result. An earlier version returned
// the zero value there, which threw away certificates that cannot be
// regenerated because their key labels are taken. Callers check the result
// even when the error is non-nil.
func withTokenLogin[T any](ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, resolvePIN PINResolver, fn func() (T, error)) (result T, err error) {
	var zero T
	if adapter.TokenLoggedIn() {
		return zero, fmt.Errorf("ca: ceremony: a token is already authenticated before logging into %q; refusing to proceed", ws.Label)
	}
	pin, err := resolvePIN()
	if err != nil {
		return zero, fmt.Errorf("ca: ceremony: resolving PIN for %q: %w", ws.Label, err)
	}
	if err := adapter.LoginToken(ctx, ws, pin, pk11.RoleUser); err != nil {
		return zero, fmt.Errorf("ca: ceremony: logging into %q: %w", ws.Label, err)
	}
	defer func() {
		logoutErr := adapter.LogoutToken(ctx)
		// fn's error explains the failure; a teardown error must not
		// replace it. result is left untouched either way.
		if logoutErr != nil && err == nil {
			err = fmt.Errorf("ca: ceremony: work on %q completed but logging out failed (the returned result is valid and must not be discarded): %w", ws.Label, logoutErr)
		}
	}()

	return fn()
}
