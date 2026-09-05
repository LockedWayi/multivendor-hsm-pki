package ca

// White-box tests for the checks ReissueIntermediate makes before it
// touches a token. Every property here is a property of a certificate or of
// a parameter struct, not of a key on an HSM, so these build certificates
// in software: an HSM would add minutes of setup and prove nothing extra
//. The token-touching half — the real rotation, the
// missing-root-key refusal, the overwrite guard — is in reissue_test.go and
// runs against every backend.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// softRoot builds a self-signed CA certificate in software, shaped like the
// one RunCeremony produces unless a field is overridden.
func softRoot(t *testing.T, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "soft test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

func TestCheckRootMaySign_AcceptsACeremonyShapedRoot(t *testing.T) {
	if err := checkRootMaySign(softRoot(t, nil), 5*365*24*time.Hour, time.Now()); err != nil {
		t.Fatalf("checkRootMaySign rejected a well-formed root: %v", err)
	}
}

// An unconstrained root — no pathLenConstraint at all — must be accepted.
// This is the case the measured MaxPathLen == -1 exists to protect: a check
// written as "MaxPathLen == 0" would reject it, and a root with no
// constraint is perfectly entitled to certify a CA beneath it.
func TestCheckRootMaySign_AcceptsRootWithNoPathLenConstraint(t *testing.T) {
	root := softRoot(t, func(c *x509.Certificate) { c.MaxPathLen = 0; c.MaxPathLenZero = false })
	if root.MaxPathLen != -1 {
		t.Fatalf("precondition: expected an unconstrained root to parse as MaxPathLen -1, got %d", root.MaxPathLen)
	}
	if err := checkRootMaySign(root, 5*365*24*time.Hour, time.Now()); err != nil {
		t.Fatalf("checkRootMaySign rejected an unconstrained root: %v", err)
	}
}

func TestCheckRootMaySign_Rejects(t *testing.T) {
	year := 365 * 24 * time.Hour
	tests := []struct {
		name     string
		root     *x509.Certificate
		validity time.Duration
		wantErr  error
	}{
		{
			name: "not a CA",
			// MaxPathLen must be cleared alongside IsCA: crypto/x509
			// refuses to create a non-CA certificate that specifies one.
			root:     softRoot(t, func(c *x509.Certificate) { c.IsCA = false; c.MaxPathLen = 0 }),
			validity: year,
			wantErr:  ErrNotAnIntermediate,
		},
		{
			// pathlen:0 means no CA may sit beneath this root, so the
			// intermediate this would produce could sign nothing.
			name:     "pathlen:0 root cannot certify a CA",
			root:     softRoot(t, func(c *x509.Certificate) { c.MaxPathLen = 0; c.MaxPathLenZero = true }),
			validity: year,
			wantErr:  ErrNotAnIntermediate,
		},
		{
			// the issuer-authority rule: the issuing certificate must assert the key
			// usage the operation needs.
			name:     "no keyCertSign",
			root:     softRoot(t, func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCRLSign }),
			validity: year,
			wantErr:  ErrNotAnIntermediate,
		},
		{
			name: "expired root",
			root: softRoot(t, func(c *x509.Certificate) {
				c.NotBefore = time.Now().Add(-2 * time.Hour)
				c.NotAfter = time.Now().Add(-time.Hour)
			}),
			validity: year,
			wantErr:  ErrIssuerNotValid,
		},
		{
			name: "root not yet valid",
			root: softRoot(t, func(c *x509.Certificate) {
				c.NotBefore = time.Now().Add(time.Hour)
				c.NotAfter = time.Now().Add(2 * time.Hour)
			}),
			validity: year,
			wantErr:  ErrIssuerNotValid,
		},
		{
			// the issuer-authority rule: the issuer must be able to cover the
			// lifetime about to be granted. Rejected, never clamped.
			name:     "intermediate would outlive the root",
			root:     softRoot(t, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(year) }),
			validity: 5 * year,
			wantErr:  ErrValidityExceedsIssuer,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRootMaySign(tc.root, tc.validity, time.Now())
			if err == nil {
				t.Fatal("checkRootMaySign accepted a root it must reject")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("checkRootMaySign error = %v, want one wrapping %v", err, tc.wantErr)
			}
		})
	}
}

// A certificate that is not self-signed is not the root of this hierarchy,
// however much its Subject claims to be. checkRootMaySign verifies the
// signature rather than comparing Subject to Issuer, because those strings
// are operator-controlled and say nothing about who actually signed
// . The fixture is built to make the two disagree: Subject
// and Issuer are identical strings, and the signature is by a different key.
func TestCheckRootMaySign_RejectsNonSelfSignedRoot(t *testing.T) {
	const sharedCN = "soft test root"

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating issuer key: %v", err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: sharedCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("creating issuer certificate: %v", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parsing issuer certificate: %v", err)
	}

	// The impostor carries the same Subject as its issuer, and its own key.
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating subject key: %v", err)
	}
	impostorTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: sharedCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	impostorDER, err := x509.CreateCertificate(rand.Reader, impostorTmpl, issuer, &subjectKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("creating impostor certificate: %v", err)
	}
	impostor, err := x509.ParseCertificate(impostorDER)
	if err != nil {
		t.Fatalf("parsing impostor certificate: %v", err)
	}

	// The property the test depends on: a Subject/Issuer comparison cannot
	// tell these apart, so only the signature check can.
	if impostor.Subject.String() != impostor.Issuer.String() {
		t.Fatalf("fixture is wrong: Subject %q != Issuer %q, so this would not test what it claims",
			impostor.Subject, impostor.Issuer)
	}
	if err := checkRootMaySign(impostor, 365*24*time.Hour, time.Now()); err == nil {
		t.Fatal("checkRootMaySign accepted a certificate whose Subject matches its Issuer but which is not self-signed")
	}
}

// checkRootMaySign's verdict depends on the instant it is given, which is
// the property that makes calling it twice worth anything. Same root, same
// requested validity, two different clocks: one inside the root's window,
// one past it.
//
// This is the unit-level stand-in for the real hazard. In
// ReissueIntermediate the two calls are separated by an HSM key generation,
// a token login and an object search, so the certificate's NotAfter is
// computed from a strictly later instant than the one validate() approved.
// Reproducing that window end-to-end would need an injectable clock;
// pinning the time-dependence here, plus the call at the template site,
// is what the fix rests on.
func TestCheckRootMaySign_VerdictDependsOnTheInstantGiven(t *testing.T) {
	year := 365 * 24 * time.Hour
	// A root with a little over a year left.
	root := softRoot(t, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-time.Hour)
		c.NotAfter = time.Now().Add(year + time.Hour)
	})

	if err := checkRootMaySign(root, year, time.Now()); err != nil {
		t.Fatalf("rejected a one-year intermediate under a root with a year and an hour left: %v", err)
	}
	// Two hours later the same request no longer fits, and the answer has
	// to change with the clock rather than with the parameters.
	later := time.Now().Add(2 * time.Hour)
	err := checkRootMaySign(root, year, later)
	if err == nil {
		t.Fatal("accepted an intermediate that would outlive the root, given a later instant")
	}
	if !errors.Is(err, ErrValidityExceedsIssuer) {
		t.Fatalf("error = %v, want one wrapping ErrValidityExceedsIssuer", err)
	}
}

// The parameter validation that runs before any key is generated
// . Every case here must be caught without an HSM being
// reachable at all, which is what makes it safe to run this as pure logic.
func TestReissueIntermediateParams_Validate(t *testing.T) {
	root := softRoot(t, nil)
	base := func() ReissueIntermediateParams {
		return ReissueIntermediateParams{
			RootWorkspace:         pk11.Workspace{Label: "root-token", Serial: "ROOTSERIAL"},
			RootKeyLabel:          "ca-root-key-v1",
			RootCert:              root,
			IntermediateWorkspace: pk11.Workspace{Label: "inter-token", Serial: "INTERSERIAL"},
			IntermediateKeyLabel:  "ca-intermediate-key-v2",
			IntermediateSubject:   pkix.Name{CommonName: "test Intermediate CA v2"},
			IntermediateValidity:  365 * 24 * time.Hour,
			RootCRLURL:            "http://pki.example.test/root.crl",
			RootCertURL:           "http://pki.example.test/root.crt",
		}
	}
	valid := base()
	if err := valid.validate(); err != nil {
		t.Fatalf("validate rejected a well-formed parameter set: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ReissueIntermediateParams)
	}{
		{"no root serial", func(p *ReissueIntermediateParams) { p.RootWorkspace.Serial = "" }},
		{"no intermediate serial", func(p *ReissueIntermediateParams) { p.IntermediateWorkspace.Serial = "" }},
		{"same token for both tiers", func(p *ReissueIntermediateParams) { p.IntermediateWorkspace.Serial = p.RootWorkspace.Serial }},
		{"empty root key label", func(p *ReissueIntermediateParams) { p.RootKeyLabel = "" }},
		{"empty intermediate key label", func(p *ReissueIntermediateParams) { p.IntermediateKeyLabel = "" }},
		{"one label for both tiers", func(p *ReissueIntermediateParams) { p.IntermediateKeyLabel = p.RootKeyLabel }},
		{"missing root CRL URL", func(p *ReissueIntermediateParams) { p.RootCRLURL = "" }},
		{"missing root cert URL", func(p *ReissueIntermediateParams) { p.RootCertURL = "" }},
		{"nil root certificate", func(p *ReissueIntermediateParams) { p.RootCert = nil }},
		// An empty subject is checkable without an HSM, so validating before mutating says reject
		// it before the first key exists. validateCSR applies the same test
		// to a leaf; this one names a CA.
		{"empty intermediate subject", func(p *ReissueIntermediateParams) { p.IntermediateSubject = pkix.Name{} }},
		{"subject with only a country", func(p *ReissueIntermediateParams) {
			p.IntermediateSubject = pkix.Name{Country: []string{"TR"}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			tc.mutate(&p)
			if err := p.validate(); err == nil {
				t.Fatal("validate accepted a parameter set it must reject")
			}
		})
	}
}
