package ca_test

// The HSM-backed half of reissue-intermediate: the rotation actually
// happening on tokens, and the refusals that can only be observed against a
// real one. Every test here runs as its own subtest per backend
// — the certificate-shape and parameter checks that need
// no token live in reissue_internal_test.go.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// ceremonyThenReissueParams runs a ceremony and returns the parameters for
// re-issuing its intermediate under the same root, with a fresh key label.
func ceremonyThenReissueParams(t *testing.T, b *ceremonyBackend) (*ca.CeremonyResult, *x509.Certificate, ca.ReissueIntermediateParams) {
	t.Helper()
	ctx := context.Background()

	result, err := ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, testCeremonyParams(b))
	if err != nil {
		t.Fatalf("RunCeremony: %v", err)
	}
	rootCert, err := x509.ParseCertificate(result.RootCertDER)
	if err != nil {
		t.Fatalf("parsing root cert: %v", err)
	}
	return result, rootCert, ca.ReissueIntermediateParams{
		RootWorkspace: b.rootWS,
		RootPIN:       func() ([]byte, error) { return []byte(b.rootPIN), nil },
		RootKeyLabel:  b.rootKeyLabel(),
		RootCurve:     pk11.P256,
		RootCert:      rootCert,

		IntermediateWorkspace: b.interWS,
		IntermediatePIN:       func() ([]byte, error) { return []byte(b.interPIN), nil },
		// v2: rotation provisions the NEXT version alongside the previous
		// one, it never overwrites a label.
		IntermediateKeyLabel: b.label("inter-key-v2"),
		IntermediateSubject:  pkix.Name{CommonName: "test Intermediate CA v2"},
		IntermediateCurve:    pk11.P256,

		RootCRLURL:  testRootCRLURL,
		RootCertURL: testRootCertURL,
	}
}

// The Done-when criterion for this sub-task: a new intermediate, over a new
// key, signed by the *existing* root — and the previous intermediate still
// valid, because that overlap is what makes rotation a transition rather
// than an outage.
func TestReissueIntermediate_ProducesNewIntermediateUnderExistingRoot(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()
		ceremony, rootCert, params := ceremonyThenReissueParams(t, b)

		out, err := ca.ReissueIntermediate(ctx, b.adapter, pk11.SessionOptions{}, params)
		if err != nil {
			t.Fatalf("ReissueIntermediate: %v", err)
		}
		newInter, err := x509.ParseCertificate(out.IntermediateCertDER)
		if err != nil {
			t.Fatalf("parsing re-issued intermediate: %v", err)
		}
		oldInter, err := x509.ParseCertificate(ceremony.IntermediateCertDER)
		if err != nil {
			t.Fatalf("parsing original intermediate: %v", err)
		}

		// Signed by the root that already exists — no new root was minted.
		if err := newInter.CheckSignatureFrom(rootCert); err != nil {
			t.Fatalf("re-issued intermediate is not validly signed by the existing root: %v", err)
		}
		// A different key: this is a rotation, not a re-certification of
		// the same key under a new certificate.
		newPub, ok := newInter.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("re-issued intermediate carries a %T public key, want ECDSA", newInter.PublicKey)
		}
		oldPub, ok := oldInter.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("original intermediate carries a %T public key, want ECDSA", oldInter.PublicKey)
		}
		if newPub.Equal(oldPub) {
			t.Fatal("re-issued intermediate carries the SAME public key as the original — this is not a rotation")
		}
		// Distinct serial: two certificates from one CA sharing a serial
		// would make revocation ambiguous.
		if newInter.SerialNumber.Cmp(oldInter.SerialNumber) == 0 {
			t.Fatalf("re-issued intermediate reuses serial %s", newInter.SerialNumber)
		}
		// The transition window: the previous intermediate must still
		// verify. Re-issuing does not revoke what it succeeds.
		if err := oldInter.CheckSignatureFrom(rootCert); err != nil {
			t.Fatalf("re-issue invalidated the previous intermediate: %v", err)
		}

		// Same constraints as a ceremony-produced intermediate — a
		// rotation that quietly widened the hierarchy could not be
		// reviewed by diffing the two certificates.
		if !newInter.IsCA || newInter.MaxPathLen != 0 || !newInter.MaxPathLenZero {
			t.Fatalf("re-issued intermediate: IsCA=%v MaxPathLen=%d MaxPathLenZero=%v, want true/0/true",
				newInter.IsCA, newInter.MaxPathLen, newInter.MaxPathLenZero)
		}
		if newInter.KeyUsage&x509.KeyUsageCertSign == 0 || newInter.KeyUsage&x509.KeyUsageCRLSign == 0 {
			t.Fatalf("re-issued intermediate KeyUsage = %v, want certSign|crlSign", newInter.KeyUsage)
		}
		if len(newInter.CRLDistributionPoints) != 1 || newInter.CRLDistributionPoints[0] != testRootCRLURL {
			t.Fatalf("re-issued intermediate CRLDistributionPoints = %v, want [%s]", newInter.CRLDistributionPoints, testRootCRLURL)
		}
		if len(newInter.IssuingCertificateURL) != 1 || newInter.IssuingCertificateURL[0] != testRootCertURL {
			t.Fatalf("re-issued intermediate IssuingCertificateURL = %v, want [%s]", newInter.IssuingCertificateURL, testRootCertURL)
		}
		// The AKI must point at the same root the old one pointed at, or
		// relying parties cannot build the path.
		if string(newInter.AuthorityKeyId) != string(rootCert.SubjectKeyId) {
			t.Fatalf("re-issued intermediate AuthorityKeyId does not match the root's SubjectKeyId")
		}

		if b.adapter.TokenLoggedIn() {
			t.Fatal("ReissueIntermediate left a token authenticated after returning")
		}
	})
}

// The safety property the whole operation turns on: a wrong root label must
// fail closed, never fall back to generating a root. If it created one, the
// new intermediate would chain to a root nobody trusts and the failure
// would surface at every relying party at once.
func TestReissueIntermediate_FailsClosedWhenRootKeyIsMissing(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()
		_, _, params := ceremonyThenReissueParams(t, b)

		missingLabel := b.label("root-key-that-does-not-exist")
		params.RootKeyLabel = missingLabel
		params.IntermediateKeyLabel = b.label("inter-key-v3")

		_, err := ca.ReissueIntermediate(ctx, b.adapter, pk11.SessionOptions{}, params)
		if err == nil {
			t.Fatal("ReissueIntermediate succeeded against a root key label that does not exist")
		}
		if !errors.Is(err, ca.ErrKeyNotFound) {
			t.Fatalf("error = %v, want one wrapping ca.ErrKeyNotFound", err)
		}

		// And it must not have created the key it could not find. This is
		// the assertion that distinguishes "failed closed" from "failed
		// after minting a second root".
		if keyExistsOnToken(t, ctx, b, b.rootWS, b.rootPIN, missingLabel) {
			t.Fatalf("ReissueIntermediate created a root key labeled %q after failing to find it — it must never generate a root", missingLabel)
		}

		if b.adapter.TokenLoggedIn() {
			t.Fatal("ReissueIntermediate left a token authenticated after failing")
		}
	})
}

// the key lifecycle: rotation provisions the next version, it never overwrites
// a label in place. Overwriting would make rotation a breaking change for
// everything holding a certificate under the old key.
func TestReissueIntermediate_RefusesToOverwriteAnExistingIntermediateLabel(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()
		_, _, params := ceremonyThenReissueParams(t, b)

		// The label the ceremony already used.
		params.IntermediateKeyLabel = b.interKeyLabel()

		if _, err := ca.ReissueIntermediate(ctx, b.adapter, pk11.SessionOptions{}, params); err == nil {
			t.Fatal("ReissueIntermediate overwrote an intermediate key label that was already in use")
		}
		if b.adapter.TokenLoggedIn() {
			t.Fatal("ReissueIntermediate left a token authenticated after failing")
		}
	})
}

// A label addresses a key; it does not identify one.
// Signing under a key the supplied root certificate does not attest to
// would produce an intermediate that verifies against nothing, so the
// mismatch must be caught before the signature.
func TestReissueIntermediate_RejectsRootCertThatDoesNotMatchTheRootKey(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()
		_, _, params := ceremonyThenReissueParams(t, b)

		// A different, unrelated root: correct shape, wrong key.
		otherRoot := unrelatedSoftRoot(t)
		params.RootCert = otherRoot
		params.IntermediateKeyLabel = b.label("inter-key-v4")

		_, err := ca.ReissueIntermediate(ctx, b.adapter, pk11.SessionOptions{}, params)
		if err == nil {
			t.Fatal("ReissueIntermediate signed under a root key the supplied certificate does not certify")
		}
		if !errors.Is(err, ca.ErrKeyCertMismatch) {
			t.Fatalf("error = %v, want one wrapping ca.ErrKeyCertMismatch", err)
		}
		if b.adapter.TokenLoggedIn() {
			t.Fatal("ReissueIntermediate left a token authenticated after failing")
		}
	})
}

// The certificates a re-issued intermediate produces must chain to the
// original root through real path validation, not merely pass a one-hop
// signature check — that is what a relying party actually does.
func TestReissueIntermediate_LeafChainsToTheOriginalRoot(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()
		_, rootCert, params := ceremonyThenReissueParams(t, b)
		params.IntermediateKeyLabel = b.label("inter-key-v5")

		out, err := ca.ReissueIntermediate(ctx, b.adapter, pk11.SessionOptions{}, params)
		if err != nil {
			t.Fatalf("ReissueIntermediate: %v", err)
		}
		newInter, err := x509.ParseCertificate(out.IntermediateCertDER)
		if err != nil {
			t.Fatalf("parsing re-issued intermediate: %v", err)
		}

		roots := x509.NewCertPool()
		roots.AddCert(rootCert)
		if _, err := newInter.Verify(x509.VerifyOptions{
			Roots:       roots,
			CurrentTime: time.Now(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Fatalf("re-issued intermediate does not chain to the original root under path validation: %v", err)
		}
	})
}

// keyExistsOnToken reports whether a private key with label is present on
// ws. It logs the token in for the check and back out afterwards, so it can
// be called after an operation that is expected to have left nothing
// authenticated.
func keyExistsOnToken(t *testing.T, ctx context.Context, b *ceremonyBackend, ws pk11.Workspace, pin, label string) bool {
	t.Helper()
	if err := b.adapter.LoginToken(ctx, ws, []byte(pin), pk11.RoleUser); err != nil {
		t.Fatalf("LoginToken for the existence check: %v", err)
	}
	defer func() {
		if err := b.adapter.LogoutToken(ctx); err != nil {
			t.Fatalf("LogoutToken after the existence check: %v", err)
		}
	}()

	s, err := b.adapter.OpenSession(ctx, ws, pk11.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession for the existence check: %v", err)
	}
	defer b.adapter.CloseSession(ctx, s)

	free, err := pk11.LabelIsFree(ctx, b.adapter, s, pk11.ClassPrivateKey, label)
	if err != nil {
		t.Fatalf("LabelIsFree(%q): %v", label, err)
	}
	return !free
}

// unrelatedSoftRoot builds a correctly-shaped, self-signed CA certificate in
// software over a key that exists nowhere on any token. It is the "right
// shape, wrong key" fixture: everything checkRootMaySign inspects passes,
// so only the key-matches-certificate check can reject it.
func unrelatedSoftRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "unrelated test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
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
