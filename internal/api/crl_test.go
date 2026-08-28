package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/api"
)

// issueTestCert issues a certificate against srv and returns it, parsed.
func issueTestCert(t *testing.T, srvURL string, cn string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

	resp, err := http.Post(srvURL+"/certificates", "application/x-pem-file", bytes.NewReader(csrPEM))
	if err != nil {
		t.Fatalf("POST /certificates: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("issue status = %d, want %d; body: %s", resp.StatusCode, http.StatusCreated, body)
	}
	block, _ := pem.Decode(body)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func revokeTestCert(t *testing.T, srvURL string, serial fmt.Stringer) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srvURL+"/certificates/"+serial.String()+"/revoke", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	return resp
}

func fetchCRL(t *testing.T, srvURL string) *x509.RevocationList {
	t.Helper()
	resp, err := http.Get(srvURL + "/crl")
	if err != nil {
		t.Fatalf("GET /crl: %v", err)
	}
	defer resp.Body.Close()
	der, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading CRL body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /crl status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, der)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	return crl
}

func TestRevoke_Success(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	cert := issueTestCert(t, srv.URL, "to-revoke.example.test")

	resp := revokeTestCert(t, srv.URL, cert.SerialNumber)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	rec, ok := registry.Get(cert.SerialNumber)
	if !ok {
		t.Fatal("record disappeared after revoke")
	}
	if rec.Status != api.StatusRevoked {
		t.Fatalf("status = %q, want %q", rec.Status, api.StatusRevoked)
	}
}

func TestRevoke_UnknownSerialFails(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/certificates/999999999999/revoke", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST revoke: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestRevoke_IsIdempotent(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	cert := issueTestCert(t, srv.URL, "revoke-twice.example.test")

	first := revokeTestCert(t, srv.URL, cert.SerialNumber)
	first.Body.Close()
	if first.StatusCode != http.StatusNoContent {
		t.Fatalf("first revoke status = %d, want %d", first.StatusCode, http.StatusNoContent)
	}

	second := revokeTestCert(t, srv.URL, cert.SerialNumber)
	second.Body.Close()
	if second.StatusCode != http.StatusNoContent {
		t.Fatalf("second revoke status = %d, want %d (revocation should be idempotent)", second.StatusCode, http.StatusNoContent)
	}
}

func TestCRL_ContainsRevokedSerial(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	cert := issueTestCert(t, srv.URL, "in-crl.example.test")
	resp := revokeTestCert(t, srv.URL, cert.SerialNumber)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	crl := fetchCRL(t, srv.URL)
	if err := crl.CheckSignatureFrom(c.Certificate()); err != nil {
		t.Fatalf("CheckSignatureFrom(ca): %v", err)
	}

	found := false
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("revoked serial %v not found in CRL entries %+v", cert.SerialNumber, crl.RevokedCertificateEntries)
	}
}

func TestCRL_EmptyWhenNothingRevoked(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	crl := fetchCRL(t, srv.URL)
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("CRL has %d entries, want 0", len(crl.RevokedCertificateEntries))
	}
	if err := crl.CheckSignatureFrom(c.Certificate()); err != nil {
		t.Fatalf("CheckSignatureFrom(ca): %v", err)
	}
}

// TestCRL_RevocationInvalidatesCache guards against a real bug found while
// manually smoke-testing a running server: a long CRL validity window
// (crl_validity_hours) means the *first* GET /crl populates a cache good
// for that whole window. Without invalidating it on revoke, a certificate
// revoked after that first fetch would not appear in the CRL until
// nextUpdate — up to the full validity window later — even though nothing
// about "don't serve a stale CRL past nextUpdate" was violated. A
// revocation must be visible on the next fetch, not on the next natural
// cache expiry.
func TestCRL_RevocationInvalidatesCache(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	// Populate the cache before anything is revoked.
	initial := fetchCRL(t, srv.URL)
	if len(initial.RevokedCertificateEntries) != 0 {
		t.Fatalf("initial CRL has %d entries, want 0", len(initial.RevokedCertificateEntries))
	}

	cert := issueTestCert(t, srv.URL, "cache-invalidation.example.test")
	resp := revokeTestCert(t, srv.URL, cert.SerialNumber)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	after := fetchCRL(t, srv.URL)
	found := false
	for _, entry := range after.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("revoked serial %v missing from CRL fetched after revoke, despite an earlier CRL fetch having cached a validity window of 24h — cache was not invalidated on revoke", cert.SerialNumber)
	}
}

// TestCRL_OpenSSLVerify is sub-task 2.5's own Done-when criterion: openssl
// crl -verify accepts the served CRL against the CA certificate, and a
// revoked serial appears in it.
func TestCRL_OpenSSLVerify(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found on PATH")
	}
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	cert := issueTestCert(t, srv.URL, "openssl-crl-check.example.test")
	resp := revokeTestCert(t, srv.URL, cert.SerialNumber)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	crlResp, err := http.Get(srv.URL + "/crl")
	if err != nil {
		t.Fatalf("GET /crl: %v", err)
	}
	defer crlResp.Body.Close()
	der, err := io.ReadAll(crlResp.Body)
	if err != nil {
		t.Fatalf("reading CRL: %v", err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	crlPath := filepath.Join(dir, "crl.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate().Raw}), 0644); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}
	if err := os.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0644); err != nil {
		t.Fatalf("WriteFile(crl): %v", err)
	}

	out, err := exec.Command("openssl", "crl", "-verify", "-CAfile", caPath, "-in", crlPath, "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl crl -verify: %v: %s", err, out)
	}

	textOut, err := exec.Command("openssl", "crl", "-in", crlPath, "-text", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl crl -text: %v: %s", err, textOut)
	}
	hexSerial := strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes()))
	if !strings.Contains(strings.ToUpper(string(textOut)), hexSerial) {
		t.Fatalf("revoked serial %s (hex) not found in openssl's CRL text output:\n%s", hexSerial, textOut)
	}
}

// TestCRL_NumberSurvivesRestart guards RFC 5280 §5.2.3's monotonicity
// requirement across a process restart. A counter starting from zero each
// time the service starts would reissue low numbers that verifiers holding
// a higher-numbered CRL may then ignore — silently, and including its
// revocations. Two independently constructed servers over the same CA stand
// in for a restart.
func TestCRL_NumberSurvivesRestart(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)

	first := httptest.NewServer(api.NewServer(c, adapter, ws, api.NewRegistry(), 24*time.Hour, rootArtifacts, testLogger()))
	beforeRestart := fetchCRL(t, first.URL)
	first.Close()

	// A brand-new server with a brand-new in-memory registry: the same
	// state a restarted process starts from.
	second := httptest.NewServer(api.NewServer(c, adapter, ws, api.NewRegistry(), 24*time.Hour, rootArtifacts, testLogger()))
	defer second.Close()
	afterRestart := fetchCRL(t, second.URL)

	if afterRestart.Number.Cmp(beforeRestart.Number) <= 0 {
		t.Fatalf("CRL number went backwards across a restart: %v then %v", beforeRestart.Number, afterRestart.Number)
	}
}

// TestCRL_NumberIncreasesWithinOneRun covers the other half: two CRLs
// generated inside the same wall-clock second must still differ.
func TestCRL_NumberIncreasesWithinOneRun(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	first := fetchCRL(t, srv.URL)

	// Force regeneration rather than waiting out the cache.
	cert := issueTestCert(t, srv.URL, "crl-number.example.test")
	resp := revokeTestCert(t, srv.URL, cert.SerialNumber)
	resp.Body.Close()

	second := fetchCRL(t, srv.URL)
	if second.Number.Cmp(first.Number) <= 0 {
		t.Fatalf("CRL number did not increase within one run: %v then %v", first.Number, second.Number)
	}
}

// TestCRL_ThisUpdateIsBackdated checks the clock-skew allowance: a verifier
// whose clock trails this host's must not see a CRL that is not valid yet.
func TestCRL_ThisUpdateIsBackdated(t *testing.T) {
	c, adapter, ws, rootArtifacts := newTestCA(t)
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, api.NewRegistry(), 24*time.Hour, rootArtifacts, testLogger()))
	defer srv.Close()

	crl := fetchCRL(t, srv.URL)
	if !crl.ThisUpdate.Before(time.Now()) {
		t.Fatalf("CRL ThisUpdate %v is not backdated relative to now", crl.ThisUpdate)
	}
}
