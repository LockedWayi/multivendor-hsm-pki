package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/api"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// csrPEMFor builds a PEM-encoded CSR for cn, signed by priv.
func csrPEMFor(t *testing.T, priv *ecdsa.PrivateKey, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestIssueCertificate_Success(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf.example.test"},
	}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file", bytes.NewReader(csrPEM))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusCreated, body)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("response is not a PEM certificate: %s", body)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if err := cert.CheckSignatureFrom(c.Certificate()); err != nil {
		t.Fatalf("CheckSignatureFrom(ca): %v", err)
	}

	if len(registry.All()) != 1 {
		t.Fatalf("registry has %d records, want 1", len(registry.All()))
	}
	rec, ok := registry.Get(cert.SerialNumber)
	if !ok {
		t.Fatal("issued certificate was not recorded in the registry")
	}
	if rec.Status != api.StatusValid {
		t.Fatalf("recorded status = %q, want %q", rec.Status, api.StatusValid)
	}
}

func TestIssueCertificate_MalformedBodyRejected(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file", strings.NewReader("this is not a CSR"))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if len(registry.All()) != 0 {
		t.Fatalf("registry has %d records, want 0 after a rejected request", len(registry.All()))
	}
}

func TestIssueCertificate_BrokenSignatureRejected(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "bad-sig.example.test"},
	}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	tampered := append([]byte(nil), der...)
	tampered[len(tampered)-1] ^= 0xFF // corrupts the trailing signature BIT STRING
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})

	resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file", bytes.NewReader(csrPEM))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if len(registry.All()) != 0 {
		t.Fatalf("registry has %d records, want 0 after a rejected request", len(registry.All()))
	}
}

func TestIssueCertificate_UnsupportedKeyTypeRejected(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ed25519.example.test"},
	}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file", bytes.NewReader(csrPEM))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if len(registry.All()) != 0 {
		t.Fatalf("registry has %d records, want 0 after a rejected request", len(registry.All()))
	}
}

// TestIssueCertificate_AdapterErrorDoesNotLeakDetail covers Phase 2
// sub-task 2.7's other failure path: an adapter-level failure (here, the
// adapter having been closed — the same failure mode as a service mid-
// shutdown or an HSM connection drop) must surface as a 500 whose body
// never contains internal error detail, only a fixed generic message
// (CLAUDE.md §3.4).
func TestIssueCertificate_AdapterErrorDoesNotLeakDetail(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	adapter.Close()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "adapter-down.example.test"},
	}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file", bytes.NewReader(csrPEM))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusInternalServerError, body)
	}
	for _, leak := range []string{"ErrAdapterClosed", "pkcs11:", "ca: HSM sign", "ca: OpenSession"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("response body leaked internal detail (%q): %s", leak, body)
		}
	}
	if len(registry.All()) != 0 {
		t.Fatalf("registry has %d records, want 0 after a failed request", len(registry.All()))
	}
}

func TestIssueCertificate_OversizedBodyRejected(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	oversized := bytes.Repeat([]byte("A"), 128*1024) // well past the 64 KiB limit
	resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file", bytes.NewReader(oversized))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
	if len(registry.All()) != 0 {
		t.Fatalf("registry has %d records, want 0 after a rejected request", len(registry.All()))
	}
}

// TestIssueCertificate_ConcurrentRequests is sub-task 2.8's Done-when
// criterion. Before the anchor-login change this failed reliably: PKCS#11
// authenticates a token for the whole application, so the second concurrent
// request's C_Login returned CKR_USER_ALREADY_LOGGED_IN, and the first
// request's C_Logout de-authenticated the second one mid-signature. Every
// other test in Phases 1 and 2 is sequential, which is exactly why the
// defect survived to be found by hand.
func TestIssueCertificate_ConcurrentRequests(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	const concurrent = 8
	var wg sync.WaitGroup
	errs := make([]error, concurrent)
	serials := make([]string, concurrent)

	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				errs[i] = err
				return
			}
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: fmt.Sprintf("concurrent-%d.example.test", i)},
			}, priv)
			if err != nil {
				errs[i] = err
				return
			}
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

			resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file", bytes.NewReader(csrPEM))
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusCreated {
				errs[i] = fmt.Errorf("status %d: %s", resp.StatusCode, body)
				return
			}
			block, _ := pem.Decode(body)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				errs[i] = err
				return
			}
			if err := cert.CheckSignatureFrom(c.Certificate()); err != nil {
				errs[i] = fmt.Errorf("CheckSignatureFrom: %w", err)
				return
			}
			serials[i] = cert.SerialNumber.String()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent request %d failed: %v", i, err)
		}
	}
	seen := make(map[string]bool, concurrent)
	for _, s := range serials {
		if seen[s] {
			t.Fatalf("duplicate serial %s across concurrent issuances", s)
		}
		seen[s] = true
	}
	if len(registry.All()) != concurrent {
		t.Fatalf("registry has %d records, want %d", len(registry.All()), concurrent)
	}
}

// TestIssueCertificate_ReturnsFullChain pins sub-task 3b.2's requirement
// that issuance hands back a path a relying party can actually build with:
// the leaf, then the intermediate that signed it.
//
// It also pins what must NOT be there. The root is absent by design — it is
// the trust anchor, and a relying party that accepted a root handed to it by
// the same server that issued the certificate would not be verifying
// anything.
func TestIssueCertificate_ReturnsFullChain(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrPEM := csrPEMFor(t, priv, "chain.example.test")

	resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file", bytes.NewReader(csrPEM))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	var certs []*x509.Certificate
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("unexpected PEM block type %q in the response", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing a returned certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) != 2 {
		t.Fatalf("response carries %d certificates, want 2 (leaf then intermediate)", len(certs))
	}
	leaf, intermediate := certs[0], certs[1]
	if leaf.IsCA {
		t.Fatal("the first certificate is a CA; the leaf must come first")
	}
	if !intermediate.IsCA {
		t.Fatal("the second certificate is not a CA; the issuing intermediate must come second")
	}
	if err := leaf.CheckSignatureFrom(intermediate); err != nil {
		t.Fatalf("returned leaf is not signed by the returned intermediate: %v", err)
	}

	// The chain the response carries must verify to the root the ceremony
	// produced, with no certificate fetched from anywhere else.
	rootBlock, _ := pem.Decode(rootArtifacts.CertPEM)
	if rootBlock == nil {
		t.Fatal("root artifact is not PEM")
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing root: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("returned chain does not verify to the ceremony root: %v", err)
	}

	for _, cert := range certs {
		if cert.Equal(root) {
			t.Fatal("the response includes the root certificate; the trust anchor must not be served alongside the chain")
		}
	}
}

// TestRootArtifactEndpoints checks that the URLs baked into the
// intermediate's CDP and AIA extensions at ceremony time actually resolve to
// the artifacts they name. A CDP pointing at nothing means no relying party
// can ever learn the intermediate was revoked.
func TestRootArtifactEndpoints(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, api.NewRegistry(), 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	t.Run("GET /root.crt serves the ceremony root", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/root.crt")
		if err != nil {
			t.Fatalf("GET /root.crt: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		block, _ := pem.Decode(body)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("response is not a CERTIFICATE PEM block")
		}
		root, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing served root: %v", err)
		}
		if err := root.CheckSignatureFrom(root); err != nil {
			t.Fatalf("served root is not self-signed, so it is not a trust anchor: %v", err)
		}
	})

	t.Run("GET /root.crl serves the ceremony root CRL", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/root.crl")
		if err != nil {
			t.Fatalf("GET /root.crl: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		block, _ := pem.Decode(body)
		if block == nil || block.Type != "X509 CRL" {
			t.Fatal("response is not an X509 CRL PEM block")
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			t.Fatalf("parsing served root CRL: %v", err)
		}
		// The root CRL covers the intermediate and nothing else, so a fresh
		// ceremony's CRL is empty. It must never carry the leaf revocations
		// that GET /crl serves -- those are the intermediate's business.
		if len(crl.RevokedCertificateEntries) != 0 {
			t.Fatalf("root CRL carries %d entries, want 0", len(crl.RevokedCertificateEntries))
		}
	})

	t.Run("the intermediate's CDP and AIA point at these paths", func(t *testing.T) {
		cert := c.Certificate()
		if len(cert.CRLDistributionPoints) == 0 {
			t.Fatal("the intermediate carries no CRL distribution point")
		}
		if len(cert.IssuingCertificateURL) == 0 {
			t.Fatal("the intermediate carries no AIA CA-Issuers pointer")
		}
		if !strings.HasSuffix(cert.CRLDistributionPoints[0], "/root.crl") {
			t.Fatalf("CDP %q does not end in /root.crl, the path this server serves", cert.CRLDistributionPoints[0])
		}
		if !strings.HasSuffix(cert.IssuingCertificateURL[0], "/root.crt") {
			t.Fatalf("AIA %q does not end in /root.crt, the path this server serves", cert.IssuingCertificateURL[0])
		}
	})
}
