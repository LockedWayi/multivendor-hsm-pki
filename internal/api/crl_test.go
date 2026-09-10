package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
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
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
		defer srv.Close()

		cert := issueTestCert(t, srv.URL, "to-revoke.example.test")

		resp := revokeTestCert(t, srv.URL, cert.SerialNumber)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke status = %d, want %d", resp.StatusCode, http.StatusNoContent)
		}

		rec, ok, err := records.Get(context.Background(), cert.SerialNumber)
		if err != nil {
			t.Fatalf("store Get: %v", err)
		}
		if !ok {
			t.Fatal("record disappeared after revoke")
		}
		if rec.Status != store.StatusRevoked {
			t.Fatalf("status = %q, want %q", rec.Status, store.StatusRevoked)
		}
	})
}

func TestRevoke_UnknownSerialFails(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	})
}

func TestRevoke_IsIdempotent(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	})
}

func TestCRL_ContainsRevokedSerial(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	})
}

func TestCRL_EmptyWhenNothingRevoked(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
		defer srv.Close()

		crl := fetchCRL(t, srv.URL)
		if len(crl.RevokedCertificateEntries) != 0 {
			t.Fatalf("CRL has %d entries, want 0", len(crl.RevokedCertificateEntries))
		}
		if err := crl.CheckSignatureFrom(c.Certificate()); err != nil {
			t.Fatalf("CheckSignatureFrom(ca): %v", err)
		}
	})
}

// TestCRL_RevocationInvalidatesCache: a revocation must be visible on the
// next fetch, not at the next cache expiry. With a long validity window
// the first GET /crl would otherwise hide later revocations until
// nextUpdate.
func TestCRL_RevocationInvalidatesCache(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
			t.Fatalf("revoked serial %v missing from CRL fetched after revoke, despite an earlier CRL fetch having cached a validity window of 24h; cache was not invalidated on revoke", cert.SerialNumber)
		}
	})
}

// TestCRL_OpenSSLVerify: openssl crl -verify accepts the served CRL and a
// revoked serial appears in it.
func TestCRL_OpenSSLVerify(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		if _, err := exec.LookPath("openssl"); err != nil {
			t.Skip("openssl not found on PATH")
		}
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
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
	})
}

// TestCRL_NumberSurvivesRestart: CRL numbers stay monotonic across a
// process restart (RFC 5280 §5.2.3). Two servers over the same CA stand in
// for a restart.
func TestCRL_NumberSurvivesRestart(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)

		first := httptest.NewServer(api.NewServer(c, adapter, ws, store.NewMemory(), 24*time.Hour, rootArtifacts, testLogger()))
		beforeRestart := fetchCRL(t, first.URL)
		first.Close()

		// A new server with a new in-memory store.
		second := httptest.NewServer(api.NewServer(c, adapter, ws, store.NewMemory(), 24*time.Hour, rootArtifacts, testLogger()))
		defer second.Close()
		afterRestart := fetchCRL(t, second.URL)

		if afterRestart.Number.Cmp(beforeRestart.Number) <= 0 {
			t.Fatalf("CRL number went backwards across a restart: %v then %v", beforeRestart.Number, afterRestart.Number)
		}
	})
}

// TestCRL_NumberIncreasesWithinOneRun: two CRLs generated in one second
// still differ.
func TestCRL_NumberIncreasesWithinOneRun(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
		defer srv.Close()

		first := fetchCRL(t, srv.URL)

		// Force regeneration.
		cert := issueTestCert(t, srv.URL, "crl-number.example.test")
		resp := revokeTestCert(t, srv.URL, cert.SerialNumber)
		resp.Body.Close()

		second := fetchCRL(t, srv.URL)
		if second.Number.Cmp(first.Number) <= 0 {
			t.Fatalf("CRL number did not increase within one run: %v then %v", first.Number, second.Number)
		}
	})
}

// TestCRL_ThisUpdateIsBackdated: a verifier with a slow clock must not see
// a CRL that is not valid yet.
func TestCRL_ThisUpdateIsBackdated(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, store.NewMemory(), 24*time.Hour, rootArtifacts, testLogger()))
		defer srv.Close()

		crl := fetchCRL(t, srv.URL)
		if !crl.ThisUpdate.Before(time.Now()) {
			t.Fatalf("CRL ThisUpdate %v is not backdated relative to now", crl.ThisUpdate)
		}
	})
}

// TestCRL_RevocationSurvivesRestart: issue, revoke, restart the service
// over the same store, and the revoked serial is still in the CRL. The
// in-memory registry this replaced could not pass this.
func TestCRL_RevocationSurvivesRestart(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		ctx := context.Background()
		dbPath := filepath.Join(t.TempDir(), "ca.db")

		openStore := func() *store.SQLite {
			t.Helper()
			s, err := store.OpenSQLite(ctx, dbPath, nil, nil)
			if err != nil {
				t.Fatalf("OpenSQLite: %v", err)
			}
			return s
		}

		// First run: issue, then revoke.
		records := openStore()
		first := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		resp, err := http.Post(first.URL+"/certificates", "application/x-pem-file",
			bytes.NewReader(csrPEMFor(t, priv, "survives-restart.example.test")))
		if err != nil {
			t.Fatalf("POST /certificates: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("issue status = %d, want 201; body: %s", resp.StatusCode, body)
		}
		block, _ := pem.Decode(body)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing issued leaf: %v", err)
		}

		revokeResp, err := http.Post(first.URL+"/certificates/"+leaf.SerialNumber.String()+"/revoke", "application/json", nil)
		if err != nil {
			t.Fatalf("POST revoke: %v", err)
		}
		revokeResp.Body.Close()
		if revokeResp.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke status = %d, want 204", revokeResp.StatusCode)
		}

		beforeRestart := fetchCRL(t, first.URL)
		if !crlContains(beforeRestart, leaf.SerialNumber) {
			t.Fatal("the CRL does not list the certificate that was just revoked")
		}

		// The process ends.
		first.Close()
		if err := records.Close(); err != nil {
			t.Fatalf("closing the store: %v", err)
		}

		// Second run over the same file.
		reopened := openStore()
		defer reopened.Close()
		second := httptest.NewServer(api.NewServer(c, adapter, ws, reopened, 24*time.Hour, rootArtifacts, testLogger()))
		defer second.Close()

		afterRestart := fetchCRL(t, second.URL)
		if !crlContains(afterRestart, leaf.SerialNumber) {
			t.Fatalf("serial %s is absent from the CRL after a restart: a revoked certificate has reappeared as valid",
				leaf.SerialNumber)
		}
		if afterRestart.Number.Cmp(beforeRestart.Number) <= 0 {
			t.Fatalf("CRL number went backwards across a restart: %v then %v (RFC 5280 §5.2.3)",
				beforeRestart.Number, afterRestart.Number)
		}
	})
}

func crlContains(crl *x509.RevocationList, serial *big.Int) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// TestCRL_NextUpdateNeverOutlivesTheIssuer pins the clamp in currentCRL.
// A shorter CRL is valid; refusing would remove the CA's ability to
// publish revocations in the window where re-issuance is most likely.
func TestCRL_NextUpdateNeverOutlivesTheIssuer(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)

		// A validity far beyond the intermediate's lifetime.
		crlValidity := 100 * 365 * 24 * time.Hour
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, store.NewMemory(), crlValidity, rootArtifacts, testLogger()))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/crl")
		if err != nil {
			t.Fatalf("GET /crl: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			t.Fatalf("parsing CRL: %v", err)
		}

		issuerNotAfter := c.Certificate().NotAfter
		if crl.NextUpdate.After(issuerNotAfter) {
			t.Fatalf("CRL nextUpdate %s is after the issuer's NotAfter %s: the CRL claims authority past its issuer's life",
				crl.NextUpdate, issuerNotAfter)
		}
		if !crl.NextUpdate.Equal(issuerNotAfter) {
			t.Fatalf("CRL nextUpdate %s was not clamped to the issuer's NotAfter %s", crl.NextUpdate, issuerNotAfter)
		}
	})
}
