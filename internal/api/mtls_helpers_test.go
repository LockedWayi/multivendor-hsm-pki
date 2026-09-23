package api_test

// Scaffolding for the two surfaces. Every test that writes goes through
// the authenticated listener with a client certificate this CA issued,
// because that is the only way a write reaches the service.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

// The identities the helpers authorise. URIs, as an operator would
// configure them.
const (
	testIssuer  = "urn:hsm-pki:test:issuer"
	testRevoker = "urn:hsm-pki:test:revoker"
)

// testServers is one service on its two listeners.
type testServers struct {
	// public is the plain-HTTP surface: CRLs, certificates, probes.
	public *httptest.Server
	// tls is the mutual-TLS surface with everything on it.
	tls *httptest.Server
	// client is authenticated as testIssuer, which startServers lists as
	// both an issuer and a revoker.
	client *http.Client
	root   *x509.Certificate
	ca     *ca.CA
	store  store.Store
	// seeded is how many records the helper wrote into the store before
	// the test began: one, the issuer's own certificate.
	seeded int
}

func (ts *testServers) Close() {
	ts.tls.Close()
	ts.public.Close()
}

// startServers starts both surfaces over c with testIssuer authorised to
// issue and revoke.
func startServers(t *testing.T, c *ca.CA, adapter pk11.VendorAdapter, ws pk11.Workspace, records store.Store, crlValidity time.Duration, root api.RootArtifacts) *testServers {
	t.Helper()
	return startServersOn(t, httptest.NewUnstartedServer(nil), c, adapter, ws, records, crlValidity, root,
		api.Authorization{Issuers: entitled(testIssuer), Revokers: []string{testIssuer}})
}

// startServersOn is startServers over a public listener the test created
// early, for a test whose base URL has to exist before the CA does, and
// with an explicit authorisation.
func startServersOn(t *testing.T, public *httptest.Server, c *ca.CA, adapter pk11.VendorAdapter, ws pk11.Workspace, records store.Store, crlValidity time.Duration, root api.RootArtifacts, authz api.Authorization) *testServers {
	t.Helper()

	rootCert, err := x509.ParseCertificate(root.CertDER)
	if err != nil {
		t.Fatalf("parsing the root: %v", err)
	}

	handlers := api.NewServer(api.Config{
		Profiles:      testProfiles(),
		Issuer:        c,
		Adapter:       adapter,
		Workspace:     ws,
		Records:       records,
		CRLValidity:   crlValidity,
		Root:          root,
		Logger:        testLogger(),
		Authorization: authz,
	})

	public.Config.Handler = handlers.Public
	public.Start()

	tlsSrv := httptest.NewUnstartedServer(handlers.Authenticated)
	tlsSrv.TLS = api.TLSConfig(issueServerIdentity(t, c), rootCert)
	tlsSrv.StartTLS()

	ts := &testServers{public: public, tls: tlsSrv, root: rootCert, ca: c, store: records}
	issuerCert := issueClientCertificate(t, c, records, testIssuer)
	ts.seeded = 1
	ts.client = ts.clientWith(t, issuerCert)
	return ts
}

// clientWith returns an HTTP client that trusts the ceremony root and
// presents cert. A nil cert presents nothing.
func (ts *testServers) clientWith(t *testing.T, cert *tls.Certificate) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ts.root)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

// issueServerIdentity issues the listener's own certificate over an
// in-memory key. The production path holds that key on the token;
// TestAuthenticatedListener_ServesAnHSMHeldIdentity covers it.
func issueServerIdentity(t *testing.T, c *ca.CA) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	leaf, err := c.Issue(csr, tlsServer())
	if err != nil {
		t.Fatalf("issuing the server identity: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{leaf.Raw, c.Certificate().Raw},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}

// issueClientCertificate issues a client certificate carrying identity as
// a URI SAN, records it in the store as the service would, and returns it
// with its in-memory key, ready for a TLS client.
func issueClientCertificate(t *testing.T, c *ca.CA, records store.Store, identity string) *tls.Certificate {
	t.Helper()
	leaf, priv := issueClientLeaf(t, c, identity)
	if err := records.Record(context.Background(), store.CertRecord{
		Serial:   leaf.SerialNumber,
		Subject:  leaf.Subject,
		NotAfter: leaf.NotAfter,
		Status:   store.StatusValid,
	}); err != nil {
		t.Fatalf("recording the client certificate: %v", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{leaf.Raw, c.Certificate().Raw},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}

// issueClientLeaf issues a client certificate without recording it.
func issueClientLeaf(t *testing.T, c *ca.CA, identity string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	u, err := url.Parse(identity)
	if err != nil {
		t.Fatalf("parsing identity %q: %v", identity, err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "client " + identity},
		URIs:    []*url.URL{u},
	}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	leaf, err := c.Issue(csr, tlsClient())
	if err != nil {
		t.Fatalf("issuing the client certificate: %v", err)
	}
	return leaf, priv
}
