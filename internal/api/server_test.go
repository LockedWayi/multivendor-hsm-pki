package api_test

import (
	"bytes"
	"context"
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
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
	"github.com/LockedWayi/hsm-pki-platform/internal/store"
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
	records := store.NewMemory()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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

	if records.Len() != 1 {
		t.Fatalf("store holds %d records, want 1", records.Len())
	}
	rec, ok, err := records.Get(context.Background(), cert.SerialNumber)
	if err != nil {
		t.Fatalf("store Get: %v", err)
	}
	if !ok {
		t.Fatal("issued certificate was not recorded in the store")
	}
	if rec.Status != store.StatusValid {
		t.Fatalf("recorded status = %q, want %q", rec.Status, store.StatusValid)
	}
}

func TestIssueCertificate_MalformedBodyRejected(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	records := store.NewMemory()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file", strings.NewReader("this is not a CSR"))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if records.Len() != 0 {
		t.Fatalf("store holds %d records, want 0 after a rejected request", records.Len())
	}
}

func TestIssueCertificate_BrokenSignatureRejected(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	records := store.NewMemory()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	if records.Len() != 0 {
		t.Fatalf("store holds %d records, want 0 after a rejected request", records.Len())
	}
}

func TestIssueCertificate_UnsupportedKeyTypeRejected(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	records := store.NewMemory()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	if records.Len() != 0 {
		t.Fatalf("store holds %d records, want 0 after a rejected request", records.Len())
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
	records := store.NewMemory()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	if records.Len() != 0 {
		t.Fatalf("store holds %d records, want 0 after a failed request", records.Len())
	}
}

func TestIssueCertificate_OversizedBodyRejected(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	records := store.NewMemory()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	if records.Len() != 0 {
		t.Fatalf("store holds %d records, want 0 after a rejected request", records.Len())
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
	records := store.NewMemory()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	if records.Len() != concurrent {
		t.Fatalf("store holds %d records, want %d", records.Len(), concurrent)
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
	records := store.NewMemory()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, store.NewMemory(), 24*time.Hour, rootArtifacts, testLogger()))
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

// TestIntermediateCertEndpoint covers GET /intermediate.crt, the AIA
// CA-Issuers target of every leaf this service issues.
//
// A relying party that holds only a leaf follows this URL to obtain the
// certificate that signed it. The endpoint therefore has to serve the
// service's *own* intermediate — not the root, and not whatever certificate
// happens to be at hand — or path building silently ends at the wrong
// issuer.
func TestIntermediateCertEndpoint(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, store.NewMemory(), 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + api.IntermediateCertPath)
	if err != nil {
		t.Fatalf("GET %s: %v", api.IntermediateCertPath, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("response is not a CERTIFICATE PEM block")
	}
	served, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing served intermediate: %v", err)
	}
	if !served.Equal(c.Certificate()) {
		t.Fatalf("served certificate is %q, want this service's own intermediate %q",
			served.Subject, c.Certificate().Subject)
	}
	// The distinction that matters: this is the issuer, not the trust
	// anchor. A self-signed certificate here would mean the endpoint is
	// handing out a root, which /root.crt exists for and which a relying
	// party must obtain out of band anyway.
	if err := served.CheckSignatureFrom(served); err == nil {
		t.Fatal("served certificate is self-signed, so it is a root, not the intermediate")
	}
}

// TestIntermediateCertEndpoint_MissingIssuerFailsHonestly pins the absent
// case. NewServer takes the issuer by value and cannot reject a nil one, so
// the handler must answer 503 rather than 200 with an empty body: a relying
// party handed a successful, empty response has no way to tell "the issuer
// is unavailable" from "the issuer is this zero-length certificate".
func TestIntermediateCertEndpoint_MissingIssuerFailsHonestly(t *testing.T) {
	srv := httptest.NewServer(api.NewServer(nil, nil, pk11.Workspace{}, store.NewMemory(), 24*time.Hour, api.RootArtifacts{}, testLogger()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + api.IntermediateCertPath)
	if err != nil {
		t.Fatalf("GET %s: %v", api.IntermediateCertPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// TestIssuedLeafDistributionPointsResolve is sub-task 3b.4's Done-when
// criterion, end to end: the URLs inside a freshly issued certificate are
// fetched, and what comes back is the CRL that governs *that* leaf and the
// certificate that actually signed it.
//
// Note the ordering the test has to perform, because a deployment performs
// the same one. A certificate's extensions are fixed by its signature, so
// the CA must know the service's external URL before it issues anything —
// which means the listener's address has to exist before the handler is
// built. httptest.NewUnstartedServer gives exactly that: a bound listener
// whose address is known, with the handler attached afterwards. In
// production the same ordering is why ca.base_url is operator-supplied
// configuration rather than something the process discovers about itself.
func TestIssuedLeafDistributionPointsResolve(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()

	c, adapter, ws, rootArtifacts := newTestCAAt(t, baseURL)
	srv.Config.Handler = api.NewServer(c, adapter, ws, store.NewMemory(), 24*time.Hour, rootArtifacts, testLogger())
	srv.Start()
	defer srv.Close()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	resp, err := http.Post(srv.URL+"/certificates", "application/x-pem-file",
		bytes.NewReader(csrPEMFor(t, priv, "resolve.example.test")))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	block, _ := pem.Decode(body)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing issued leaf: %v", err)
	}

	if len(leaf.CRLDistributionPoints) != 1 || len(leaf.IssuingCertificateURL) != 1 {
		t.Fatalf("leaf carries CDP %v and AIA %v, want exactly one of each",
			leaf.CRLDistributionPoints, leaf.IssuingCertificateURL)
	}
	cdpURL := leaf.CRLDistributionPoints[0]
	aiaURL := leaf.IssuingCertificateURL[0]

	t.Run("the AIA CA-Issuers URL returns the certificate that signed the leaf", func(t *testing.T) {
		issuer := getCertificate(t, aiaURL)
		if err := leaf.CheckSignatureFrom(issuer); err != nil {
			t.Fatalf("the certificate at %s did not sign the leaf: %v", aiaURL, err)
		}
		// AKI/SKI is what a path builder actually matches on, so a served
		// certificate that verifies but whose key identifier does not match
		// would still break automated path building.
		if !bytes.Equal(leaf.AuthorityKeyId, issuer.SubjectKeyId) {
			t.Fatalf("leaf AKI %x does not match the served issuer's SKI %x", leaf.AuthorityKeyId, issuer.SubjectKeyId)
		}
	})

	t.Run("the CRL distribution point returns a CRL this leaf's issuer signed", func(t *testing.T) {
		crl := getCRL(t, cdpURL)
		if err := crl.CheckSignatureFrom(c.Certificate()); err != nil {
			t.Fatalf("the CRL at %s was not signed by the leaf's issuer: %v", cdpURL, err)
		}
	})

	// The strongest form of "the CRL that governs that leaf": revoke it and
	// confirm it appears at the URL the certificate itself names. A CDP that
	// serves a valid but unrelated CRL would pass every check above and
	// still leave the certificate unrevocable in practice.
	t.Run("revoking the leaf makes it appear at its own CDP", func(t *testing.T) {
		revokeResp, err := http.Post(srv.URL+"/certificates/"+leaf.SerialNumber.String()+"/revoke", "application/json", nil)
		if err != nil {
			t.Fatalf("POST revoke: %v", err)
		}
		defer revokeResp.Body.Close()
		if revokeResp.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke status = %d, want 204", revokeResp.StatusCode)
		}

		crl := getCRL(t, cdpURL)
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				return
			}
		}
		t.Fatalf("serial %s is not listed in the CRL served at its own distribution point %s",
			leaf.SerialNumber, cdpURL)
	})
}

// getCertificate fetches a PEM certificate from url.
func getCertificate(t *testing.T, url string) *x509.Certificate {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200", url, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("GET %s did not return a CERTIFICATE PEM block", url)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the certificate served at %s: %v", url, err)
	}
	return cert
}

// getCRL fetches a DER CRL from url — the encoding GET /crl serves, which is
// what a relying party following a distribution point expects.
func getCRL(t *testing.T, url string) *x509.RevocationList {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200", url, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		t.Fatalf("parsing the CRL served at %s: %v", url, err)
	}
	return crl
}

// TestLeafDistributionFor covers URL composition on its own, without an HSM.
// The end-to-end proof that these paths match real routes is
// TestIssuedLeafDistributionPointsResolve; this covers the shapes of
// baseURL an operator may reasonably write in config.yaml.
func TestLeafDistributionFor(t *testing.T) {
	for _, tc := range []struct {
		name, base, wantCRL, wantIssuer string
	}{
		{
			"bare origin",
			"https://pki.example.test",
			"https://pki.example.test/crl",
			"https://pki.example.test/intermediate.crt",
		},
		{
			// Tolerated rather than rejected: a trailing slash is a typo an
			// operator should not have to lose a certificate over, and the
			// resulting URL is unambiguous either way.
			"trailing slash",
			"https://pki.example.test/",
			"https://pki.example.test/crl",
			"https://pki.example.test/intermediate.crt",
		},
		{
			// A CA served under a path on a shared host: the prefix has to
			// survive, or every URL points at the host's root.
			"path prefix",
			"https://shared.example.test/pki",
			"https://shared.example.test/pki/crl",
			"https://shared.example.test/pki/intermediate.crt",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := api.LeafDistributionFor(tc.base)
			if got.CRLURL != tc.wantCRL {
				t.Fatalf("CRLURL = %q, want %q", got.CRLURL, tc.wantCRL)
			}
			if got.IssuerCertURL != tc.wantIssuer {
				t.Fatalf("IssuerCertURL = %q, want %q", got.IssuerCertURL, tc.wantIssuer)
			}
		})
	}
}
