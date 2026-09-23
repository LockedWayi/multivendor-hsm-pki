package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

// postProfile sends a CN-only request under the named profile, or under
// none when profile is empty, and returns the response.
func postProfile(t *testing.T, ts *testServers, profile, cn string, dns []string) *http.Response {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
	}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	url := ts.tls.URL + "/certificates"
	if profile != "" {
		url += "?profile=" + profile
	}
	resp, err := ts.client.Post(url, "application/x-pem-file", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// TestIssueCertificate_ProfileIsRequiredAndNeverDefaulted: no profile,
// an unknown one, and a wrong case are each a 400 that names what exists,
// and nothing is recorded on any of them.
func TestIssueCertificate_ProfileIsRequiredAndNeverDefaulted(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		for _, name := range []string{"", "default", "TLS-CLIENT", "tls-client%20"} {
			t.Run("profile="+name, func(t *testing.T) {
				resp := postProfile(t, ts, name, "leaf.example.test", nil)
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400; body: %s", resp.StatusCode, body)
				}
				if !strings.Contains(string(body), "tls-client") || !strings.Contains(string(body), "code-signing") {
					t.Fatalf("the refusal does not list the available profiles: %s", body)
				}
				if records.Len() != ts.seeded {
					t.Fatalf("store holds %d records, want %d: a refused request was recorded", records.Len(), ts.seeded)
				}
			})
		}
	})
}

// TestIssueCertificate_ProfileDecidesTheCertificate: the same request
// under two profiles is two different certificates, and a request the
// profile's policy refuses is a 400 with the reason, nothing recorded.
func TestIssueCertificate_ProfileDecidesTheCertificate(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		issued := func(profile, cn string, dns []string) *x509.Certificate {
			t.Helper()
			resp := postProfile(t, ts, profile, cn, dns)
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("%s: status = %d, want 201; body: %s", profile, resp.StatusCode, body)
			}
			block, _ := pem.Decode(body)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			return cert
		}

		server := issued("tls-server", "pki.example.test", []string{"pki.example.test"})
		client := issued("tls-client", "alice", nil)
		if len(server.ExtKeyUsage) != 1 || server.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
			t.Errorf("tls-server EKUs = %v", server.ExtKeyUsage)
		}
		if len(client.ExtKeyUsage) != 1 || client.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("tls-client EKUs = %v", client.ExtKeyUsage)
		}
		if records.Len() != ts.seeded+2 {
			t.Fatalf("store holds %d records, want %d", records.Len(), ts.seeded+2)
		}

		// tls-server requires a name; a CN-only request is refused with
		// the profile's reason and is not recorded.
		resp := postProfile(t, ts, "tls-server", "pki.example.test", nil)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "subject alternative name") {
			t.Fatalf("tls-server without a name: status = %d, body %s; want 400 naming the missing SAN", resp.StatusCode, body)
		}
		if records.Len() != ts.seeded+2 {
			t.Fatalf("a refused request was recorded")
		}
	})
}
