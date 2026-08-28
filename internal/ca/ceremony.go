package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// DefaultIntermediateValidity is how long a freshly ceremony-produced
// intermediate certificate is valid for. Shorter than DefaultRootValidity —
// the intermediate is the certificate this platform expects to routinely
// re-issue (CLAUDE.md §3.7), the root is not.
const DefaultIntermediateValidity = 5 * 365 * 24 * time.Hour

// DefaultRootCRLValidity is how long the root's CRL is valid for. Long-lived
// by design: the root stays offline between ceremonies (docs/phases/
// phase-3b-pki-hardening.md, "How the root CRL is produced" decision), so
// refreshing it means re-running the ceremony, not a recurring online step.
const DefaultRootCRLValidity = 5 * 365 * 24 * time.Hour

// CeremonyParams configures RunCeremony. Root and intermediate are
// configured as two independent tokens — never one — per the "Where the
// root key lives relative to the intermediate" decision in
// docs/phases/phase-3b-pki-hardening.md: the whole point is that nothing
// downstream of this ceremony ever needs to name the root's token.
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

	// RootCRLURL is where the root's CRL will be served from. It becomes the
	// intermediate certificate's CRL distribution point, and it is required
	// rather than optional: the root is offline, so its CRL is the only
	// channel by which a relying party can ever learn the intermediate was
	// revoked. A ceremony is irreversible — an intermediate signed without a
	// CDP can never gain one without bringing the root back online — so the
	// operator is made to decide the distribution point before the signature
	// happens, not after.
	RootCRLURL string
	// RootCertURL is where the root certificate will be served from. It
	// becomes the intermediate's AIA CA-Issuers pointer, letting a relying
	// party that lacks the root build the path. Required for the same
	// irreversibility reason as RootCRLURL.
	RootCertURL string
}

// validate checks every parameter that can be checked without touching an
// HSM, and is called before RunCeremony generates any key.
//
// The ordering is the point: a ceremony is irreversible and refuses to
// overwrite a key label it has already used, so a parameter mistake caught
// *after* the first key pair exists costs the operator a manual cleanup on
// the token before they can retry. Everything knowable up front is therefore
// rejected up front (CLAUDE.md §3.4).
func (p *CeremonyParams) validate() error {
	// Serial, not Label and not SlotID, is what identifies a token — see
	// pkcs11.Workspace's doc comment. Comparing labels would reject two
	// legitimately distinct tokens that happen to share a name; comparing
	// slot IDs would fail to notice one token presented at two slots, which
	// is precisely the case this guard exists to catch.
	if p.RootWorkspace.Serial == "" || p.IntermediateWorkspace.Serial == "" {
		return fmt.Errorf("ca: ceremony requires both workspaces to carry a token serial number; got root=%q intermediate=%q — a Workspace built by hand rather than returned by Workspaces() will not have one",
			p.RootWorkspace.Serial, p.IntermediateWorkspace.Serial)
	}
	if p.RootWorkspace.Serial == p.IntermediateWorkspace.Serial {
		return fmt.Errorf("ca: ceremony refuses to run with root and intermediate on the same token (serial %q, labels %q and %q) — see phase-3b-pki-hardening.md's root token isolation decision",
			p.RootWorkspace.Serial, p.RootWorkspace.Label, p.IntermediateWorkspace.Label)
	}
	if p.RootKeyLabel == "" || p.IntermediateKeyLabel == "" {
		return fmt.Errorf("ca: ceremony requires both key labels to be set")
	}
	if p.RootKeyLabel == p.IntermediateKeyLabel {
		return fmt.Errorf("ca: ceremony refuses to use one key label (%q) for both tiers", p.RootKeyLabel)
	}
	if err := validateDistributionURL("RootCRLURL", p.RootCRLURL); err != nil {
		return err
	}
	if err := validateDistributionURL("RootCertURL", p.RootCertURL); err != nil {
		return err
	}
	// An intermediate that outlives its issuer advertises a validity the
	// chain cannot honor: RFC 5280 path validation requires every
	// certificate in the path to be valid at the time of use, so the chain
	// dies with the root regardless of what the intermediate claims.
	// Rejected rather than silently clamped to the root's NotAfter —
	// clamping would hand the operator a certificate whose lifetime differs
	// from the one they asked for, discovered long after the one-shot
	// ceremony they cannot easily repeat (CLAUDE.md §3.4).
	if p.IntermediateValidity > p.RootValidity {
		return fmt.Errorf("ca: intermediate validity (%s) exceeds root validity (%s) — the intermediate would outlive the root that signed it",
			p.IntermediateValidity, p.RootValidity)
	}
	return nil
}

// validateDistributionURL rejects a URL that would be embedded into a
// certificate this ceremony can never re-issue without the root. Only
// http/https are accepted: RFC 5280 §4.2.1.13 names HTTP as the interop
// baseline for CRL distribution points, and a scheme a relying party cannot
// fetch is the same as no distribution point at all.
func validateDistributionURL(field, raw string) error {
	if raw == "" {
		return fmt.Errorf("ca: ceremony requires %s to be set — see CeremonyParams for why it is not optional", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("ca: %s is not a valid URL: %w", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("ca: %s must be an http or https URL, got scheme %q", field, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("ca: %s has no host: %q", field, raw)
	}
	return nil
}

// CeremonyResult is everything RunCeremony hands back: DER-encoded public
// artifacts only — root certificate, intermediate certificate, and the
// root's initial CRL. No private key material of any kind is included or
// ever leaves either token (CLAUDE.md §3.1): both key pairs are generated
// on, and never extracted from, the HSM.
type CeremonyResult struct {
	RootCertDER         []byte
	IntermediateCertDER []byte
	RootCRLDER          []byte
}

// RunCeremony is the one-time, explicitly-run root and intermediate
// bootstrap for a two-tier CA hierarchy (docs/phases/
// phase-3b-pki-hardening.md, sub-task 3b.1). It is not part of the online
// service's startup path — cmd/hsm-pki-keytool's ceremony command is the
// only caller this platform ships, and it is meant to be run once, by an
// operator, before the service ever starts.
//
// The sequence: generate the intermediate's key pair on its own token first
// (its public key is needed to build the intermediate certificate, but
// nothing about generating it requires the root), then log into the root's
// token, generate the root key pair, self-sign the root certificate
// (MaxPathLen 1), sign the intermediate certificate under it (MaxPathLen 0,
// explicit), and produce the root's initial CRL. RunCeremony logs out of
// every token it logs into before returning, on every path — a ceremony
// that left a token authenticated behind it would defeat the isolation the
// two-token decision exists to provide.
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
		// Empirical token-separation check, and the reason it runs here
		// rather than in validate(): serial numbers are a metadata claim,
		// but an object search is a measurement. If these two workspaces
		// are in fact one token — a vendor presenting it at two slots with
		// two serials, or any other way the metadata could mislead — then
		// the intermediate key pair generated a moment ago is visible from
		// this session, because a label search only ever sees the token it
		// is run against.
		//
		// Placed before the root key pair is generated so that an abort
		// here leaves exactly one label used rather than two.
		interVisibleFromRoot, err := keyPairExists(ctx, adapter, params.RootWorkspace, sessionOpts, params.IntermediateKeyLabel)
		if err != nil {
			return nil, fmt.Errorf("ca: ceremony: checking token separation: %w", err)
		}
		if interVisibleFromRoot {
			return nil, fmt.Errorf("ca: ceremony aborted: the intermediate key label %q is visible from the root token (label %q, serial %q), so these are the same key space despite reporting different serials — the root must be isolated (phase-3b-pki-hardening.md)",
				params.IntermediateKeyLabel, params.RootWorkspace.Label, params.RootWorkspace.Serial)
		}
		return signRootAndIntermediate(ctx, adapter, sessionOpts, params, interPub)
	})
}

// generateCeremonyKey logs into ws, generates a fresh EC key pair labeled
// label, and returns its public key. It refuses to run against a label that
// already exists on the token — a ceremony never silently overwrites a key
// (CLAUDE.md §3.4) — and logs the token back out before returning on every
// path, including error paths.
//
// # Why the existence check is not atomic, and why that is acceptable
//
// This checks for the label and then creates it, which is a check-then-act
// with a window in between. That window cannot be closed at this layer, and
// the obvious fix — let the HSM reject the duplicate — does not exist:
// PKCS#11 places no uniqueness constraint on CKA_LABEL (it is specified as
// a description of the object), so C_GenerateKeyPair will happily create a
// second pair under a label already in use and return success. There is no
// error to catch.
//
// What closes the hole is the *use* side rather than the creation side:
// findKeyByLabel treats "more than one object with this label" as a failure
// and refuses to return a handle, so a duplicate created through this window
// surfaces as a loud error the next time anything tries to sign with that
// label, never as a silent signature under the wrong key. A ceremony is
// also a single-operator, one-shot operation, so the window is narrow in
// practice — but it is the use-side rejection, not the narrowness, that
// makes this safe.
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

// signRootAndIntermediate runs with the root token already authenticated
// (called from inside withTokenLogin by RunCeremony): it generates the root
// key pair, self-signs the root certificate, signs the intermediate
// certificate over interPub, and builds the root's initial CRL.
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
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(params.RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// The root may certify exactly one level below itself: the
		// intermediate. Nothing the intermediate signs may itself be a CA
		// (that constraint lives on the intermediate's own certificate,
		// MaxPathLenZero below) — this field is what makes a
		// standards-compliant verifier enforce it, not just this platform's
		// own issuance code.
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
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(params.IntermediateValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Explicit pathlen 0: nothing the intermediate signs may itself be a
		// CA. MaxPathLenZero must be set alongside MaxPathLen: 0 — otherwise
		// crypto/x509 treats an unset zero value as "no constraint" rather
		// than "constrained to zero".
		MaxPathLen:     0,
		MaxPathLenZero: true,
		SubjectKeyId:   interSKI,
		AuthorityKeyId: rootSKI,
		// The intermediate's revocation status is published in the *root's*
		// CRL, so this points there — not at the CRL this intermediate will
		// itself serve for its own leaves. Set at ceremony time because it
		// can never be added afterward: changing an extension means
		// re-signing, which means bringing the offline root back out.
		CRLDistributionPoints: []string{params.RootCRLURL},
		// AIA CA-Issuers: where a relying party that does not already hold
		// the root can fetch it to complete the path. No OCSP URL is set —
		// the responder does not exist until Phase 5b, and pointing at an
		// endpoint that is not there is worse than omitting the pointer.
		IssuingCertificateURL: []string{params.RootCertURL},
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, interPub, rootSigner)
	if err != nil {
		return nil, fmt.Errorf("ca: signing intermediate certificate: %w", err)
	}

	// The root's own CRL, covering the intermediate. It starts with nothing
	// revoked — this is the CRL a relying party fetches to confirm the
	// intermediate has not been revoked, not a record of any revocation
	// having happened yet.
	rootForCRL := &CA{cert: rootCert, signer: rootSigner}
	rootCRLDER, err := rootForCRL.BuildCRL(nil, now, now.Add(params.RootCRLValidity), big.NewInt(1))
	if err != nil {
		return nil, fmt.Errorf("ca: building root CRL: %w", err)
	}

	return &CeremonyResult{
		RootCertDER:         rootDER,
		IntermediateCertDER: interDER,
		RootCRLDER:          rootCRLDER,
	}, nil
}

// withTokenLogin logs into ws for the span of fn and logs back out
// afterward, on every path. It refuses to run if the adapter already holds
// some other token authenticated — a ceremony expects to own the adapter's
// anchor login exclusively for the duration of each step, never to inherit
// or silently replace one a caller left behind.
//
// # The logout is deferred, and the result survives a failed logout
//
// Two properties this function must have, both learned the hard way:
//
// The logout runs in a defer, so it happens even if fn panics. Without it,
// the invariant "this function leaves no token authenticated" would depend
// on some caller further up having deferred adapter.Close() — true today in
// cmd/hsm-pki-keytool, but a property of that caller rather than of this
// function.
//
// More importantly, a logout failure never discards a successful fn's
// result. An earlier version returned the zero value in that case, which for
// a ceremony meant the worst outcome available: the key pairs exist on the
// tokens and the certificates were signed, but the only copy of those
// certificates — held in memory, never yet written — is thrown away, and
// the ceremony cannot be re-run because its key labels are now taken. The
// artifacts are public certificates containing no secret material, so
// returning them alongside the logout error costs nothing and preserves
// irreplaceable work. Callers must therefore check the result even when the
// error is non-nil; cmd/hsm-pki-keytool writes the artifacts first and
// reports the error afterward.
func withTokenLogin[T any](ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, resolvePIN PINResolver, fn func() (T, error)) (result T, err error) {
	var zero T
	if adapter.TokenLoggedIn() {
		return zero, fmt.Errorf("ca: ceremony: a token is already authenticated before logging into %q — refusing to proceed", ws.Label)
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
		// Only surface the logout failure when fn itself succeeded —
		// otherwise fn's error is the one that explains what went wrong,
		// and replacing it with a teardown error would bury the cause.
		// result is deliberately left untouched either way.
		if logoutErr != nil && err == nil {
			err = fmt.Errorf("ca: ceremony: work on %q completed but logging out failed (the returned result is valid and must not be discarded): %w", ws.Label, logoutErr)
		}
	}()

	return fn()
}
