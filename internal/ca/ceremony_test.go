package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

const (
	testRootCRLURL  = "http://pki.example.test/root.crl"
	testRootCertURL = "http://pki.example.test/root.crt"

	// The leaf-tier equivalents: where a certificate this intermediate
	// issues tells a relying party to look. Distinct from the two above by
	// design — the root's CRL covers the intermediate, the intermediate's
	// covers the leaves.
	testLeafCRLURL    = "http://pki.example.test/crl"
	testLeafIssuerURL = "http://pki.example.test/intermediate.crt"
)

func testCeremonyParams(b *ceremonyBackend) ca.CeremonyParams {
	return ca.CeremonyParams{
		RootWorkspace: b.rootWS,
		RootPIN:       func() ([]byte, error) { return []byte(b.rootPIN), nil },
		RootKeyLabel:  b.rootKeyLabel(),
		RootSubject:   pkix.Name{CommonName: "test Root CA"},
		RootCurve:     pk11.P256,
		RootCRLURL:    testRootCRLURL,
		RootCertURL:   testRootCertURL,

		IntermediateWorkspace: b.interWS,
		IntermediatePIN:       func() ([]byte, error) { return []byte(b.interPIN), nil },
		IntermediateKeyLabel:  b.interKeyLabel(),
		IntermediateSubject:   pkix.Name{CommonName: "test Intermediate CA"},
		IntermediateCurve:     pk11.P256,
	}
}

// TestRunCeremony_ProducesVerifiableChain is sub-task 3b.1's own Done-when
// criterion: the ceremony runs against a clean two-token setup and produces
// a chain openssl accepts, with the root showing pathlen:1 and the
// intermediate pathlen:0.
func TestRunCeremony_ProducesVerifiableChain(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()

		result, err := ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, testCeremonyParams(b))
		if err != nil {
			t.Fatalf("RunCeremony: %v", err)
		}

		rootCert, err := x509.ParseCertificate(result.RootCertDER)
		if err != nil {
			t.Fatalf("parsing root cert: %v", err)
		}
		interCert, err := x509.ParseCertificate(result.IntermediateCertDER)
		if err != nil {
			t.Fatalf("parsing intermediate cert: %v", err)
		}

		if !rootCert.IsCA || rootCert.MaxPathLen != 1 || rootCert.MaxPathLenZero {
			t.Fatalf("root cert: IsCA=%v MaxPathLen=%d MaxPathLenZero=%v, want IsCA=true MaxPathLen=1 MaxPathLenZero=false",
				rootCert.IsCA, rootCert.MaxPathLen, rootCert.MaxPathLenZero)
		}
		if !interCert.IsCA || interCert.MaxPathLen != 0 || !interCert.MaxPathLenZero {
			t.Fatalf("intermediate cert: IsCA=%v MaxPathLen=%d MaxPathLenZero=%v, want IsCA=true MaxPathLen=0 MaxPathLenZero=true",
				interCert.IsCA, interCert.MaxPathLen, interCert.MaxPathLenZero)
		}
		if err := interCert.CheckSignatureFrom(rootCert); err != nil {
			t.Fatalf("intermediate cert is not validly signed by root cert: %v", err)
		}

		// CDP/AIA are set at ceremony time because they can never be added
		// afterward without bringing the offline root back out to re-sign.
		if len(interCert.CRLDistributionPoints) != 1 || interCert.CRLDistributionPoints[0] != testRootCRLURL {
			t.Fatalf("intermediate CRLDistributionPoints = %v, want [%s]", interCert.CRLDistributionPoints, testRootCRLURL)
		}
		if len(interCert.IssuingCertificateURL) != 1 || interCert.IssuingCertificateURL[0] != testRootCertURL {
			t.Fatalf("intermediate IssuingCertificateURL = %v, want [%s]", interCert.IssuingCertificateURL, testRootCertURL)
		}
		// No OCSP pointer until the responder exists in Phase 5b — pointing
		// at an endpoint that is not there is worse than omitting it.
		if len(interCert.OCSPServer) != 0 {
			t.Fatalf("intermediate OCSPServer = %v, want empty until Phase 5b", interCert.OCSPServer)
		}

		crl, err := x509.ParseRevocationList(result.RootCRLDER)
		if err != nil {
			t.Fatalf("parsing root CRL: %v", err)
		}
		if err := crl.CheckSignatureFrom(rootCert); err != nil {
			t.Fatalf("root CRL is not validly signed by root cert: %v", err)
		}
		if len(crl.RevokedCertificateEntries) != 0 {
			t.Fatalf("freshly ceremony-produced root CRL has %d entries, want 0", len(crl.RevokedCertificateEntries))
		}

		// Both tokens must be left logged out — RunCeremony owns login and
		// logout of each token for exactly the span it needs, never longer.
		if b.adapter.TokenLoggedIn() {
			t.Fatal("RunCeremony left a token authenticated after returning")
		}

		if _, err := exec.LookPath("openssl"); err != nil {
			t.Skip("openssl not found on PATH; skipping real-tooling verification")
		}

		dir := t.TempDir()
		rootPath := filepath.Join(dir, "root.pem")
		interPath := filepath.Join(dir, "intermediate.pem")
		writePEM(t, rootPath, "CERTIFICATE", result.RootCertDER)
		writePEM(t, interPath, "CERTIFICATE", result.IntermediateCertDER)
		leafPath, _ := issueTestLeaf(t, b, interCert, dir)

		out, err := exec.Command("openssl", "verify", "-CAfile", rootPath, "-untrusted", interPath, leafPath).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl verify (chain): %v: %s", err, out)
		}

		rootText, err := exec.Command("openssl", "x509", "-in", rootPath, "-text", "-noout").CombinedOutput()
		if err != nil {
			t.Fatalf("openssl x509 -text (root): %v: %s", err, rootText)
		}
		if !strings.Contains(string(rootText), "pathlen:1") {
			t.Fatalf("root cert text does not show pathlen:1:\n%s", rootText)
		}
		interText, err := exec.Command("openssl", "x509", "-in", interPath, "-text", "-noout").CombinedOutput()
		if err != nil {
			t.Fatalf("openssl x509 -text (intermediate): %v: %s", err, interText)
		}
		if !strings.Contains(string(interText), "pathlen:0") {
			t.Fatalf("intermediate cert text does not show pathlen:0:\n%s", interText)
		}
	})
}

// TestRunCeremony_RejectsSameTokenForBothRoles is the fail-closed guard
// against the one input mistake that would silently defeat the whole point
// of this phase's token-isolation decision.
func TestRunCeremony_RejectsSameTokenForBothRoles(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		params := testCeremonyParams(b)
		params.IntermediateWorkspace = params.RootWorkspace
		params.IntermediatePIN = params.RootPIN

		if _, err := ca.RunCeremony(context.Background(), b.adapter, pk11.SessionOptions{}, params); err == nil {
			t.Fatal("RunCeremony with root and intermediate on the same token succeeded, want an error")
		}
	})
}

// TestRunCeremony_DetectsSameTokenPresentedWithDifferentSerials is why the
// empirical cross-visibility check exists alongside the serial comparison.
// It fakes the case a serial check cannot catch — one token reported under
// two identities — by handing the ceremony the same real token twice with
// the serial rewritten on one copy. The serial guard passes; the
// object-visibility check must still stop it.
func TestRunCeremony_DetectsSameTokenPresentedWithDifferentSerials(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		params := testCeremonyParams(b)
		disguised := b.rootWS
		disguised.Serial = b.rootWS.Serial + "-disguised"
		params.IntermediateWorkspace = disguised
		params.IntermediatePIN = params.RootPIN

		_, err := ca.RunCeremony(context.Background(), b.adapter, pk11.SessionOptions{}, params)
		if err == nil {
			t.Fatal("RunCeremony succeeded against one token disguised as two, want an error")
		}
		if !strings.Contains(err.Error(), "same key space") {
			t.Fatalf("error did not come from the cross-visibility check: %v", err)
		}
	})
}

func TestRunCeremony_RejectsInvalidParams(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()

		tests := []struct {
			name   string
			mutate func(*ca.CeremonyParams)
		}{
			{"intermediate outlives root", func(p *ca.CeremonyParams) {
				p.RootValidity = 2 * 365 * 24 * time.Hour
				p.IntermediateValidity = 5 * 365 * 24 * time.Hour
			}},
			{"one key label for both tiers", func(p *ca.CeremonyParams) {
				p.IntermediateKeyLabel = p.RootKeyLabel
			}},
			{"empty CRL URL", func(p *ca.CeremonyParams) { p.RootCRLURL = "" }},
			{"empty cert URL", func(p *ca.CeremonyParams) { p.RootCertURL = "" }},
			{"non-http CRL URL", func(p *ca.CeremonyParams) { p.RootCRLURL = "ldap://pki.example.test/root.crl" }},
			{"CRL URL without host", func(p *ca.CeremonyParams) { p.RootCRLURL = "http:///root.crl" }},
			{"workspace without a serial", func(p *ca.CeremonyParams) { p.RootWorkspace.Serial = "" }},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				params := testCeremonyParams(b)
				tc.mutate(&params)
				if _, err := ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, params); err == nil {
					t.Fatalf("RunCeremony accepted invalid params (%s), want an error", tc.name)
				}
			})
		}

		// Every case above must have been rejected before any key was
		// created, so a valid ceremony can still run afterward against the
		// same labels. If validation had let one through far enough to
		// touch the HSM, this would fail with "refuses to overwrite an
		// existing key label".
		if _, err := ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, testCeremonyParams(b)); err != nil {
			t.Fatalf("a valid ceremony after the rejected ones failed, so validation mutated the tokens: %v", err)
		}
	})
}

// TestRunCeremony_ConcurrentRunsFailClosed drives several ceremonies at the
// same token pair simultaneously. Exactly one may win: the rest must be
// rejected by the anchor-login guard or the key-label guard, never interleave
// key generation.
func TestRunCeremony_ConcurrentRunsFailClosed(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()

		const runs = 8
		var wg sync.WaitGroup
		results := make([]*ca.CeremonyResult, runs)
		errs := make([]error, runs)

		wg.Add(runs)
		for i := 0; i < runs; i++ {
			go func(i int) {
				defer wg.Done()
				results[i], errs[i] = ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, testCeremonyParams(b))
			}(i)
		}
		wg.Wait()

		succeeded := 0
		for i := range results {
			if errs[i] == nil {
				succeeded++
			}
		}
		if succeeded != 1 {
			t.Fatalf("%d of %d concurrent ceremonies succeeded, want exactly 1; errors: %v", succeeded, runs, errs)
		}

		// The winner's key label must resolve to exactly one object. A
		// duplicate created through the check-then-act window would make
		// NewSigner fail here rather than silently sign under a wrong key.
		if err := b.adapter.LoginToken(ctx, b.interWS, []byte(b.interPIN), pk11.RoleUser); err != nil {
			t.Fatalf("LoginToken: %v", err)
		}
		defer func() { _ = b.adapter.LogoutToken(ctx) }()
		if _, err := ca.NewSigner(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, b.interKeyLabel(), pk11.P256); err != nil {
			t.Fatalf("intermediate key label does not resolve to exactly one key pair after concurrent ceremonies: %v", err)
		}
	})
}

// TestRunCeremony_ConcurrentIssuanceUnderCeremonyIntermediate is the load
// case that matters for this phase. Phase 2.8 established that issuance is
// concurrency-safe under the anchor-login model; this re-establishes it
// against an intermediate produced by the ceremony rather than by Bootstrap.
func TestRunCeremony_ConcurrentIssuanceUnderCeremonyIntermediate(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()

		result, err := ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, testCeremonyParams(b))
		if err != nil {
			t.Fatalf("RunCeremony: %v", err)
		}
		rootCert, err := x509.ParseCertificate(result.RootCertDER)
		if err != nil {
			t.Fatalf("parsing root cert: %v", err)
		}
		interCert, err := x509.ParseCertificate(result.IntermediateCertDER)
		if err != nil {
			t.Fatalf("parsing intermediate cert: %v", err)
		}

		if err := b.adapter.LoginToken(ctx, b.interWS, []byte(b.interPIN), pk11.RoleUser); err != nil {
			t.Fatalf("LoginToken: %v", err)
		}
		defer func() { _ = b.adapter.LogoutToken(ctx) }()

		signer, err := ca.NewSigner(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, b.interKeyLabel(), pk11.P256)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		intermediateCA := ca.NewCA(interCert, signer, 24*time.Hour, testLeafDistribution())

		const workers = 16
		var wg sync.WaitGroup
		leaves := make([]*x509.Certificate, workers)
		issueErrs := make([]error, workers)

		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func(i int) {
				defer wg.Done()
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					issueErrs[i] = err
					return
				}
				csrDER, err := x509.CreateCertificateRequest(rand.Reader,
					&x509.CertificateRequest{Subject: pkix.Name{CommonName: fmt.Sprintf("load-%d.example.test", i)}}, priv)
				if err != nil {
					issueErrs[i] = err
					return
				}
				csr, err := x509.ParseCertificateRequest(csrDER)
				if err != nil {
					issueErrs[i] = err
					return
				}
				leaves[i], issueErrs[i] = intermediateCA.Issue(csr)
			}(i)
		}
		wg.Wait()

		// Every leaf must be issued, chain through the intermediate to the
		// root, and carry a unique serial — a shared serial across
		// concurrent issuance would be a real defect, not a cosmetic one.
		roots := x509.NewCertPool()
		roots.AddCert(rootCert)
		intermediates := x509.NewCertPool()
		intermediates.AddCert(interCert)
		seen := make(map[string]bool, workers)

		for i := range leaves {
			if issueErrs[i] != nil {
				t.Fatalf("worker %d: Issue: %v", i, issueErrs[i])
			}
			serial := leaves[i].SerialNumber.String()
			if seen[serial] {
				t.Fatalf("worker %d produced a duplicate serial %s", i, serial)
			}
			seen[serial] = true

			if _, err := leaves[i].Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}); err != nil {
				t.Fatalf("worker %d: leaf does not chain through the ceremony intermediate to the root: %v", i, err)
			}
		}
	})
}

// TestRunCeremony_RefusesToOverwriteExistingKeyLabel proves the ceremony
// fails closed rather than silently reusing or duplicating a key label an
// earlier run already created.
func TestRunCeremony_RefusesToOverwriteExistingKeyLabel(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()

		if _, err := ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, testCeremonyParams(b)); err != nil {
			t.Fatalf("first RunCeremony: %v", err)
		}
		if _, err := ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, testCeremonyParams(b)); err == nil {
			t.Fatal("second RunCeremony against the same key labels succeeded, want an error")
		}
	})
}

// TestRunCeremony_RootKeyExtractableIsOperatorControlled proves
// CeremonyParams.RootKeyExtractable actually reaches the token's
// CKA_EXTRACTABLE attribute in both directions — asked of the token, not
// assumed from the request that was sent, the same discipline 3b.7
// established after CKA_SENSITIVE turned out to be a silent lie on one
// backend . Maintainer decision, 2026-08-31
// (docs/key-ceremony-and-recovery.md, "Deciding root-key extractability"):
// whether the root key can ever leave its token wrapped is an operator
// choice made at ceremony time, not a fixed default baked into RunCeremony —
// this is the regression test for that choice actually taking effect.
func TestRunCeremony_RootKeyExtractableIsOperatorControlled(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		for _, extractable := range []bool{true, false} {
			t.Run(fmt.Sprintf("extractable=%v", extractable), func(t *testing.T) {
				ctx := context.Background()
				params := testCeremonyParams(b)
				// Distinct labels per iteration: the ceremony refuses to
				// overwrite a key label it has already used, and this test
				// runs two ceremonies against the same pair of tokens.
				params.RootKeyLabel = b.label(fmt.Sprintf("root-key-ext-%v", extractable))
				params.IntermediateKeyLabel = b.label(fmt.Sprintf("inter-key-ext-%v", extractable))
				params.RootKeyExtractable = extractable

				if _, err := ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, params); err != nil {
					t.Fatalf("RunCeremony: %v", err)
				}

				if err := b.adapter.LoginToken(ctx, b.rootWS, []byte(b.rootPIN), pk11.RoleUser); err != nil {
					t.Fatalf("LoginToken (root): %v", err)
				}
				defer func() { _ = b.adapter.LogoutToken(ctx) }()

				s, err := b.adapter.OpenSession(ctx, b.rootWS, pk11.SessionOptions{})
				if err != nil {
					t.Fatalf("OpenSession: %v", err)
				}
				defer b.adapter.CloseSession(ctx, s)

				found, err := b.adapter.FindObjects(ctx, s, []pk11.Attribute{
					pk11.NumericAttribute(pk11.AttrClass, uint64(pk11.ClassPrivateKey)),
					{Type: pk11.AttrLabel, Value: []byte(params.RootKeyLabel)},
				})
				if err != nil {
					t.Fatalf("FindObjects: %v", err)
				}
				if len(found) != 1 {
					t.Fatalf("found %d private keys under label %q, want 1", len(found), params.RootKeyLabel)
				}

				attrs, err := b.adapter.GetAttributes(ctx, s, found[0], []pk11.AttributeType{pk11.AttrExtractable})
				if err != nil {
					t.Fatalf("GetAttributes: %v", err)
				}
				gotExtractable := len(attrs[0].Value) > 0 && attrs[0].Value[0] != 0
				if gotExtractable != extractable {
					t.Fatalf("token reports CKA_EXTRACTABLE=%v, want %v", gotExtractable, extractable)
				}
			})
		}
	})
}

// TestRunCeremony_LeafDoesNotVerifyAgainstUnrelatedRoot proves the ceremony
// output is bound to its own run (phase-3b-pki-hardening.md 3b.1's Done-when,
// "rejection of a leaf signed directly by the root of a different ceremony
// run"). The unrelated root is a plain software-generated self-signed
// certificate rather than a second HSM ceremony: PKCS#11 modules support only
// one C_Initialize per process, so a second ceremony against the same module
// cannot run in the same test binary. What the test proves — that the chain
// does not verify against a root it was not issued under — does not depend on
// how that unrelated root's key was generated.
func TestRunCeremony_LeafDoesNotVerifyAgainstUnrelatedRoot(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found on PATH")
	}
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		result, err := ca.RunCeremony(context.Background(), b.adapter, pk11.SessionOptions{}, testCeremonyParams(b))
		if err != nil {
			t.Fatalf("RunCeremony: %v", err)
		}
		interCert, err := x509.ParseCertificate(result.IntermediateCertDER)
		if err != nil {
			t.Fatalf("parsing intermediate: %v", err)
		}

		dir := t.TempDir()
		unrelatedRootPath := filepath.Join(dir, "unrelated-root.pem")
		writePEM(t, unrelatedRootPath, "CERTIFICATE", selfSignedRootDER(t, "unrelated Root CA"))
		interPath := filepath.Join(dir, "intermediate.pem")
		writePEM(t, interPath, "CERTIFICATE", result.IntermediateCertDER)
		leafPath, _ := issueTestLeaf(t, b, interCert, dir)

		out, err := exec.Command("openssl", "verify", "-CAfile", unrelatedRootPath, "-untrusted", interPath, leafPath).CombinedOutput()
		if err == nil {
			t.Fatalf("openssl verify unexpectedly succeeded against an unrelated root: %s", out)
		}
	})
}

// selfSignedRootDER returns a fresh, software-generated self-signed root
// certificate DER — used only as an "unrelated root" negative-test fixture,
// never as a stand-in for HSM-backed key custody.
func selfSignedRootDER(t *testing.T, commonName string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

// issueTestLeaf logs into the intermediate token, issues one leaf through
// ca.CA.Issue under the ceremony's intermediate, writes it as PEM under dir,
// and logs the token back out. It exists so tests can prove the ceremony's
// intermediate actually signs a working chain.
func issueTestLeaf(t *testing.T, b *ceremonyBackend, interCert *x509.Certificate, dir string) (path string, cert *x509.Certificate) {
	t.Helper()
	ctx := context.Background()

	if err := b.adapter.LoginToken(ctx, b.interWS, []byte(b.interPIN), pk11.RoleUser); err != nil {
		t.Fatalf("LoginToken (intermediate, for test leaf): %v", err)
	}
	defer func() {
		if err := b.adapter.LogoutToken(ctx); err != nil {
			t.Fatalf("LogoutToken (intermediate, after test leaf): %v", err)
		}
	}()

	signer, err := ca.NewSigner(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, b.interKeyLabel(), pk11.P256)
	if err != nil {
		t.Fatalf("NewSigner (intermediate): %v", err)
	}
	intermediateCA := ca.NewCA(interCert, signer, 24*time.Hour, testLeafDistribution())

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.test"}}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}

	leaf, err := intermediateCA.Issue(csr)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	leafPath := filepath.Join(dir, "leaf.pem")
	writePEM(t, leafPath, "CERTIFICATE", leaf.Raw)
	return leafPath, leaf
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
