package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

// postCSR sends a fresh CSR for cn through client to url and returns the
// response.
func postCSR(t *testing.T, client *http.Client, url, cn string) (*http.Response, error) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return client.Post(url+"/certificates", "application/x-pem-file", bytes.NewReader(csrPEMFor(t, priv, cn)))
}

// expectStatus reads and closes resp and fails unless it carries want.
func expectStatus(t *testing.T, resp *http.Response, want int, context string) {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s: status = %d, want %d; body: %s", context, resp.StatusCode, want, body)
	}
}

// TestWrite_PublicSurfaceRoutesNoWriteEndpoint: the plain listener has
// no path to issuance or revocation at all, so there is nothing on it for
// authentication to protect.
func TestWrite_PublicSurfaceRoutesNoWriteEndpoint(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		resp, err := postCSR(t, http.DefaultClient, ts.public.URL, "over-plain-http.example.test")
		if err != nil {
			t.Fatalf("POST /certificates over plain HTTP: %v", err)
		}
		expectStatus(t, resp, http.StatusNotFound, "POST /certificates on the public surface")

		resp, err = http.Post(ts.public.URL+"/certificates/1/revoke", "application/json", nil)
		if err != nil {
			t.Fatalf("POST revoke over plain HTTP: %v", err)
		}
		expectStatus(t, resp, http.StatusNotFound, "POST revoke on the public surface")

		if records.Len() != ts.seeded {
			t.Fatalf("store holds %d records, want %d: something was written over plain HTTP", records.Len(), ts.seeded)
		}
	})
}

// TestWrite_NoClientCertificateFailsTheHandshake: the authenticated
// listener requires a certificate at the TLS layer. A client with none
// never reaches a handler.
func TestWrite_NoClientCertificateFailsTheHandshake(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		anonymous := ts.clientWith(t, nil)
		resp, err := postCSR(t, anonymous, ts.tls.URL, "anonymous.example.test")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("a request with no client certificate got status %d, want a handshake failure", resp.StatusCode)
		}
		if !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("the failure does not name the missing certificate: %v", err)
		}
		if records.Len() != ts.seeded {
			t.Fatalf("store holds %d records, want %d", records.Len(), ts.seeded)
		}
	})
}

// TestWrite_CertificateFromAnotherCAFailsTheHandshake: a client
// certificate that does not chain to the ceremony root is refused before
// any handler runs, whatever name it carries.
func TestWrite_CertificateFromAnotherCAFailsTheHandshake(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		// An in-memory CA that issues a leaf carrying the issuer's identity.
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "somebody else's CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("CreateCertificate (foreign CA): %v", err)
		}
		foreignCA, _ := x509.ParseCertificate(caDER)
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		u, _ := url.Parse(testIssuer)
		leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "impostor"},
			URIs:         []*url.URL{u},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, foreignCA, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("CreateCertificate (foreign leaf): %v", err)
		}

		impostor := ts.clientWith(t, &tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey})
		resp, err := postCSR(t, impostor, ts.tls.URL, "impostor.example.test")
		if err == nil {
			resp.Body.Close()
			t.Fatalf("a certificate from another CA got status %d, want a handshake failure", resp.StatusCode)
		}
		if records.Len() != ts.seeded {
			t.Fatalf("store holds %d records, want %d", records.Len(), ts.seeded)
		}
	})
}

// TestWrite_UnrecordedCertificateIsRefused: a certificate that chains to
// the root and carries an authorised name is still refused when the store
// has no record of it. Chaining proves the root vouched for an issuer;
// only the store says this CA issued this certificate.
func TestWrite_UnrecordedCertificateIsRefused(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		leaf, priv := issueClientLeaf(t, c, testIssuer) // issued, never recorded
		unrecorded := ts.clientWith(t, &tls.Certificate{
			Certificate: [][]byte{leaf.Raw, c.Certificate().Raw}, PrivateKey: priv,
		})
		resp, err := postCSR(t, unrecorded, ts.tls.URL, "unrecorded.example.test")
		if err != nil {
			t.Fatalf("POST /certificates: %v", err)
		}
		expectStatus(t, resp, http.StatusForbidden, "an unrecorded client certificate")
		if records.Len() != ts.seeded {
			t.Fatalf("store holds %d records, want %d", records.Len(), ts.seeded)
		}
	})
}

// TestWrite_RevokedClientIsRefusedAtOnce: revocation is enforced on the
// next request, with no CRL fetch in between. The service reads its own
// store, which is the point of checking the store rather than the chain.
func TestWrite_RevokedClientIsRefusedAtOnce(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		// A second issuer, authorised under the same name.
		secondCert := issueClientCertificate(t, c, records, testIssuer)
		second := ts.clientWith(t, secondCert)
		resp, err := postCSR(t, second, ts.tls.URL, "before-revocation.example.test")
		if err != nil {
			t.Fatalf("POST /certificates as the second issuer: %v", err)
		}
		expectStatus(t, resp, http.StatusCreated, "the second issuer before revocation")

		// The first issuer revokes the second.
		resp, err = ts.client.Post(ts.tls.URL+"/certificates/"+secondCert.Leaf.SerialNumber.String()+"/revoke", "application/json", nil)
		if err != nil {
			t.Fatalf("POST revoke: %v", err)
		}
		expectStatus(t, resp, http.StatusNoContent, "revoking the second issuer")

		// A new connection, so the handshake runs again and the leaf is
		// re-read from the store.
		second = ts.clientWith(t, secondCert)
		resp, err = postCSR(t, second, ts.tls.URL, "after-revocation.example.test")
		if err != nil {
			t.Fatalf("POST /certificates as the revoked issuer: %v", err)
		}
		expectStatus(t, resp, http.StatusForbidden, "the second issuer after revocation")

		// The revoker is unaffected.
		resp, err = postCSR(t, ts.client, ts.tls.URL, "still-works.example.test")
		if err != nil {
			t.Fatalf("POST /certificates as the first issuer: %v", err)
		}
		expectStatus(t, resp, http.StatusCreated, "the first issuer after revoking the second")
	})
}

// TestWrite_IdentityDecidesTheOperation: an issuer cannot revoke and a
// revoker cannot issue. The two lists are separate decisions.
func TestWrite_IdentityDecidesTheOperation(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServersOn(t, httptest.NewUnstartedServer(nil), c, adapter, ws, records, 24*time.Hour, rootArtifacts,
			api.Authorization{Issuers: []string{testIssuer}, Revokers: []string{testRevoker}})
		defer ts.Close()
		revoker := ts.clientWith(t, issueClientCertificate(t, c, records, testRevoker))

		// The issuer issues.
		resp, err := postCSR(t, ts.client, ts.tls.URL, "issued.example.test")
		if err != nil {
			t.Fatalf("POST /certificates as the issuer: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("issuer: status = %d, want 201; body: %s", resp.StatusCode, body)
		}
		block, _ := pem.Decode(body)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing the issued leaf: %v", err)
		}
		revokeURL := ts.tls.URL + "/certificates/" + leaf.SerialNumber.String() + "/revoke"

		// The issuer may not revoke.
		resp, err = ts.client.Post(revokeURL, "application/json", nil)
		if err != nil {
			t.Fatalf("POST revoke as the issuer: %v", err)
		}
		expectStatus(t, resp, http.StatusForbidden, "the issuer revoking")

		// The revoker may not issue.
		resp, err = postCSR(t, revoker, ts.tls.URL, "revoker-issuing.example.test")
		if err != nil {
			t.Fatalf("POST /certificates as the revoker: %v", err)
		}
		expectStatus(t, resp, http.StatusForbidden, "the revoker issuing")

		// The revoker revokes.
		resp, err = revoker.Post(revokeURL, "application/json", nil)
		if err != nil {
			t.Fatalf("POST revoke as the revoker: %v", err)
		}
		expectStatus(t, resp, http.StatusNoContent, "the revoker revoking")

		rec, ok, err := records.Get(context.Background(), leaf.SerialNumber)
		if err != nil || !ok {
			t.Fatalf("store Get: ok=%v err=%v", ok, err)
		}
		if rec.Status != store.StatusRevoked {
			t.Fatalf("recorded status = %q, want revoked", rec.Status)
		}
	})
}

// TestWrite_CommonNameIsAnIdentityToo: a certificate with no URI SAN is
// authorised by its common name.
func TestWrite_CommonNameIsAnIdentityToo(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		// issueClientLeaf names the subject "client <identity>".
		cn := "client " + testIssuer
		ts := startServersOn(t, httptest.NewUnstartedServer(nil), c, adapter, ws, records, 24*time.Hour, rootArtifacts,
			api.Authorization{Issuers: []string{cn}, Revokers: []string{cn}})
		defer ts.Close()

		resp, err := postCSR(t, ts.client, ts.tls.URL, "by-common-name.example.test")
		if err != nil {
			t.Fatalf("POST /certificates: %v", err)
		}
		expectStatus(t, resp, http.StatusCreated, "a client authorised by common name")
	})
}

// TestClientIdentities pins the order and the shape without a token.
func TestClientIdentities(t *testing.T) {
	u1, _ := url.Parse("urn:hsm-pki:operator:alice")
	u2, _ := url.Parse("spiffe://example.test/ns/pki/sa/ca-admin")
	got := api.ClientIdentities(&x509.Certificate{
		Subject: pkix.Name{CommonName: "Alice"},
		URIs:    []*url.URL{u1, u2},
	})
	want := []string{"urn:hsm-pki:operator:alice", "spiffe://example.test/ns/pki/sa/ca-admin", "Alice"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("ClientIdentities = %v, want %v", got, want)
	}
	if got := api.ClientIdentities(&x509.Certificate{}); len(got) != 0 {
		t.Fatalf("a certificate with no URI and no CN has identities %v, want none", got)
	}
}

// TestAuthenticatedListener_ServesAnHSMHeldIdentity: the production
// listener signs its handshakes with a key that never leaves the token.
// A client that holds only the root completes a TLS 1.3 handshake against
// it, which means the CertificateVerify signature the HSM produced
// verified at the client.
func TestAuthenticatedListener_ServesAnHSMHeldIdentity(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		ctx := context.Background()

		// The TLS key, generated on the intermediate's token.
		keyLabel := b.Label("api-tls-key-v1")
		session, err := adapter.OpenSession(ctx, ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		if _, err := adapter.GenerateKeyPair(ctx, session, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: keyLabel, Sign: true, Verify: true,
		}); err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		_ = adapter.CloseSession(ctx, session)

		// Its certificate, issued by the CA over a CSR the HSM signed.
		signer, err := ca.NewSigner(ctx, adapter, ws, pk11.SessionOptions{}, keyLabel, pk11.P256)
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:     pkix.Name{CommonName: "localhost"},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		}, signer)
		if err != nil {
			t.Fatalf("CreateCertificateRequest over the HSM key: %v", err)
		}
		csr, _ := x509.ParseCertificateRequest(csrDER)
		leaf, err := c.Issue(csr)
		if err != nil {
			t.Fatalf("issuing the TLS certificate: %v", err)
		}
		certPath := filepath.Join(t.TempDir(), "tls.pem")
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		identity, err := ca.LoadServiceCertificate(ctx, adapter, ws, pk11.SessionOptions{}, c.Certificate(), ca.ServiceCertificateParams{
			KeyLabel: keyLabel, CertPath: certPath, Curve: pk11.P256,
		})
		if err != nil {
			t.Fatalf("LoadServiceCertificate: %v", err)
		}
		if _, isSigner := identity.PrivateKey.(*ca.Signer); !isSigner {
			t.Fatalf("the identity's private key is a %T, want the HSM-backed signer", identity.PrivateKey)
		}

		root, _ := x509.ParseCertificate(rootArtifacts.CertDER)
		records := store.NewMemory()
		handlers := api.NewServer(api.Config{
			Issuer: c, Adapter: adapter, Workspace: ws, Records: records, CRLValidity: 24 * time.Hour,
			Root: rootArtifacts, Logger: testLogger(),
			Authorization: api.Authorization{Issuers: []string{testIssuer}, Revokers: []string{testIssuer}},
		})
		srv := httptest.NewUnstartedServer(handlers.Authenticated)
		srv.TLS = api.TLSConfig(identity, root)
		srv.StartTLS()
		defer srv.Close()

		ts := &testServers{root: root}
		client := ts.clientWith(t, issueClientCertificate(t, c, records, testIssuer))
		resp, err := postCSR(t, client, srv.URL, "over-an-hsm-handshake.example.test")
		if err != nil {
			t.Fatalf("POST over the HSM-signed listener: %v", err)
		}
		expectStatus(t, resp, http.StatusCreated, "a write over a handshake the HSM signed")
	})
}
