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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LockedWayi/hsm-pki-platform/internal/api"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestIssueCertificate_Success(t *testing.T) {
	c := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, registry, testLogger()))
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
	c := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, registry, testLogger()))
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
	c := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, registry, testLogger()))
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
	c := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, registry, testLogger()))
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

func TestIssueCertificate_OversizedBodyRejected(t *testing.T) {
	c := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, registry, testLogger()))
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
