package responder

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

// fixture is an in-memory two-tier CA: a root, an intermediate the CA
// signs with, a store, and a responder key. No token: the responder is
// tested here on its own logic, and the HSM-backed path is exercised in
// internal/api, where the signer comes off a token.
type fixture struct {
	root, inter  *x509.Certificate
	interKey     *ecdsa.PrivateKey
	ca           *ca.CA
	records      *store.Memory
	responderKey *ecdsa.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	respKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()

	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		SubjectKeyId: []byte{1, 2, 3},
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("intermediate: %v", err)
	}
	inter, _ := x509.ParseCertificate(interDER)

	c := ca.NewCA(inter, interKey, 30*24*time.Hour, ca.LeafDistribution{
		CRLURL: "http://pki.example.test/crl", IssuerCertURL: "http://pki.example.test/intermediate.crt", OCSPURL: "http://pki.example.test/ocsp",
	})
	return &fixture{root: root, inter: inter, interKey: interKey, ca: c, records: store.NewMemory(), responderKey: respKey}
}

// newResponder builds a responder whose certificate lasts validity.
func (f *fixture) newResponder(t *testing.T, certValidity, window time.Duration) *Responder {
	t.Helper()
	p := profile.Builtin()[profile.InternalOnlyProfile]
	p.Validity = certValidity
	r, err := New(context.Background(), Config{
		Issuer: f.ca, Records: f.records, Signer: f.responderKey, Profile: p, Validity: window,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// leaf issues and records a certificate under tls-client.
func (f *fixture) leaf(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	p := profile.Builtin()["tls-client"]
	p.Validity = time.Hour
	cert, err := f.ca.Issue(csr, p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := f.records.Record(context.Background(), store.CertRecord{Serial: cert.SerialNumber, Subject: cert.Subject, NotAfter: cert.NotAfter, Status: store.StatusValid}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	return cert
}

// request builds an OCSP request for cert under issuer with hash.
func request(t *testing.T, cert, issuer *x509.Certificate, hash crypto.Hash) []byte {
	t.Helper()
	der, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: hash})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	return der
}

// parse verifies a response the way a relying party does: the signature
// under the responder certificate the response carries, that certificate
// issued by issuer with the ocspSigning usage.
func parse(t *testing.T, der []byte, cert, issuer *x509.Certificate) *ocsp.Response {
	t.Helper()
	resp, err := ocsp.ParseResponseForCert(der, cert, issuer)
	if err != nil {
		t.Fatalf("ParseResponseForCert: %v", err)
	}
	return resp
}

func TestNew_IssuesARecordedResponderCertificateUnderTheInternalProfile(t *testing.T) {
	f := newFixture(t)
	r := f.newResponder(t, 7*24*time.Hour, time.Hour)
	cert := r.Certificate()
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageOCSPSigning {
		t.Fatalf("responder EKUs = %v", cert.ExtKeyUsage)
	}
	nocheck := false
	for _, e := range cert.Extensions {
		if e.Id.Equal(profile.OIDOCSPNoCheck) {
			nocheck = true
		}
	}
	if !nocheck {
		t.Fatal("responder certificate lacks id-pkix-ocsp-nocheck")
	}
	if _, found, _ := f.records.Get(context.Background(), cert.SerialNumber); !found {
		t.Fatal("responder certificate not recorded in the store")
	}
	if cert.Subject.CommonName != "Test Intermediate OCSP Responder" {
		t.Fatalf("subject = %q", cert.Subject.CommonName)
	}
	// Any other profile is refused: the responder certificate is issued
	// under the internal-only profile and nothing else.
	if _, err := New(context.Background(), Config{Issuer: f.ca, Records: f.records, Signer: f.responderKey, Profile: profile.Builtin()["tls-client"], Validity: time.Hour}); err == nil {
		t.Fatal("New accepted a responder under tls-client")
	}
}

// TestRespond_GoodRevokedUnknown: the three answers, each verified as a
// relying party would, with unknown for a serial the store never saw.
func TestRespond_GoodRevokedUnknown(t *testing.T) {
	f := newFixture(t)
	r := f.newResponder(t, 7*24*time.Hour, time.Hour)
	ctx := context.Background()
	good := f.leaf(t, "good")
	revoked := f.leaf(t, "revoked")
	revokedAt := time.Now().Add(-time.Minute)
	if err := f.records.Revoke(ctx, revoked.SerialNumber, store.ReasonKeyCompromise, revokedAt); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
		der, out := r.Respond(ctx, request(t, good, f.inter, hash))
		if out.Error != "" || out.Status != ocsp.Good {
			t.Fatalf("good under %v: outcome %+v", hash, out)
		}
		resp := parse(t, der, good, f.inter)
		if resp.Status != ocsp.Good || resp.SerialNumber.Cmp(good.SerialNumber) != 0 {
			t.Fatalf("good under %v: parsed %+v", hash, resp)
		}
		if resp.Certificate == nil || !resp.Certificate.Equal(r.Certificate()) {
			t.Fatalf("response does not carry the responder certificate")
		}
		if !resp.NextUpdate.After(resp.ThisUpdate) || resp.NextUpdate.Sub(resp.ThisUpdate) > time.Hour+2*clockSkewAllowance {
			t.Fatalf("window = %s..%s", resp.ThisUpdate, resp.NextUpdate)
		}
	}

	der, out := r.Respond(ctx, request(t, revoked, f.inter, crypto.SHA1))
	if out.Status != ocsp.Revoked {
		t.Fatalf("revoked: outcome %+v", out)
	}
	resp := parse(t, der, revoked, f.inter)
	if resp.Status != ocsp.Revoked || resp.RevocationReason != ocsp.KeyCompromise || resp.RevokedAt.Sub(store.NormalizeTime(revokedAt)).Abs() > time.Second {
		t.Fatalf("revoked: parsed status=%d reason=%d at=%s", resp.Status, resp.RevocationReason, resp.RevokedAt)
	}

	// Never issued: a certificate signed by nobody this CA knows, with a
	// serial the store has never seen. The response is unknown, and
	// never good.
	stranger := &x509.Certificate{SerialNumber: big.NewInt(999999999), RawIssuer: f.inter.RawSubject}
	der, out = r.Respond(ctx, request(t, stranger, f.inter, crypto.SHA1))
	if out.Status != ocsp.Unknown {
		t.Fatalf("unknown: outcome %+v", out)
	}
	if resp, err := ocsp.ParseResponse(der, f.inter); err != nil || resp.Status != ocsp.Unknown {
		t.Fatalf("unknown: parsed %+v, %v", resp, err)
	}
}

// TestRespond_ErrorResponses: each error is a well-formed OCSPResponse
// with the status RFC 6960 gives it, never an HTTP-level failure.
func TestRespond_ErrorResponses(t *testing.T) {
	f := newFixture(t)
	r := f.newResponder(t, 7*24*time.Hour, time.Hour)
	ctx := context.Background()
	leaf := f.leaf(t, "leaf")

	status := func(der []byte) ocsp.ResponseStatus {
		t.Helper()
		_, err := ocsp.ParseResponse(der, nil)
		var re ocsp.ResponseError
		if !errors.As(err, &re) {
			t.Fatalf("not an error response: %v", err)
		}
		return re.Status
	}

	if der, out := r.Respond(ctx, []byte("not DER")); out.Error != "malformedRequest" || status(der) != ocsp.Malformed {
		t.Fatalf("garbage: %+v", out)
	}
	if der, out := r.Respond(ctx, nil); out.Error != "malformedRequest" || status(der) != ocsp.Malformed {
		t.Fatalf("empty: %+v", out)
	}
	// About another issuer: the same serial, hashed under the root, is a
	// request this responder is not authoritative for.
	if der, out := r.Respond(ctx, request(t, leaf, f.root, crypto.SHA1)); out.Error != "unauthorized" || status(der) != ocsp.Unauthorized {
		t.Fatalf("other issuer: %+v", out)
	}
	// A hash the responder does not compute the issuer under.
	if der, out := r.Respond(ctx, request(t, leaf, f.inter, crypto.SHA512)); out.Error != "malformedRequest" || status(der) != ocsp.Malformed {
		t.Fatalf("sha512: %+v", out)
	}
}

// failingStore is a Store whose Get fails, for the tryLater path.
type failingStore struct {
	store.Store
}

func (failingStore) Get(context.Context, *big.Int) (store.CertRecord, bool, error) {
	return store.CertRecord{}, false, errors.New("database is locked")
}

// TestRespond_StoreUnavailableIsTryLater: without the store the honest
// answer is "ask again", never good.
func TestRespond_StoreUnavailableIsTryLater(t *testing.T) {
	f := newFixture(t)
	leaf := f.leaf(t, "leaf")
	p := profile.Builtin()[profile.InternalOnlyProfile]
	r, err := New(context.Background(), Config{Issuer: f.ca, Records: f.records, Signer: f.responderKey, Profile: p, Validity: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.records = failingStore{f.records}
	der, out := r.Respond(context.Background(), request(t, leaf, f.inter, crypto.SHA1))
	if out.Error != "tryLater" {
		t.Fatalf("outcome %+v", out)
	}
	var re ocsp.ResponseError
	if _, err := ocsp.ParseResponse(der, nil); !errors.As(err, &re) || re.Status != ocsp.TryLater {
		t.Fatalf("not tryLater: %v", err)
	}
}

// TestRespond_ExpiredCertificateIsTryLaterUntilRenewed: the point-of-use
// check. A certificate valid when the responder started has expired; it
// answers tryLater, and after Renew it answers again under a new one.
func TestRespond_ExpiredCertificateIsTryLaterUntilRenewed(t *testing.T) {
	f := newFixture(t)
	r := f.newResponder(t, 2*time.Second, time.Hour)
	ctx := context.Background()
	leaf := f.leaf(t, "leaf")
	first := r.Certificate()

	if _, out := r.Respond(ctx, request(t, leaf, f.inter, crypto.SHA1)); out.Status != ocsp.Good {
		t.Fatalf("before expiry: %+v", out)
	}
	time.Sleep(2500 * time.Millisecond)
	// The cached response would still be served if the cache were
	// consulted before the certificate; a fresh serial avoids the cache
	// and reaches the check.
	fresh := f.leaf(t, "fresh")
	if _, out := r.Respond(ctx, request(t, fresh, f.inter, crypto.SHA1)); out.Error != "tryLater" {
		t.Fatalf("after expiry: %+v", out)
	}
	if !r.dueForRenewal(time.Now()) {
		t.Fatal("an expired certificate is not due for renewal")
	}
	if err := r.Renew(ctx); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if r.Certificate().SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("Renew kept the same certificate")
	}
	der, out := r.Respond(ctx, request(t, fresh, f.inter, crypto.SHA1))
	if out.Status != ocsp.Good {
		t.Fatalf("after renewal: %+v", out)
	}
	parse(t, der, fresh, f.inter)
}

// TestRespond_CacheAndInvalidation: a second request is served from the
// cache; a revocation drops it, so the next answer is revoked at once
// rather than at nextUpdate; unknown serials are never cached.
func TestRespond_CacheAndInvalidation(t *testing.T) {
	f := newFixture(t)
	r := f.newResponder(t, 7*24*time.Hour, time.Hour)
	ctx := context.Background()
	leaf := f.leaf(t, "leaf")
	req := request(t, leaf, f.inter, crypto.SHA1)

	first, out := r.Respond(ctx, req)
	if out.Cached {
		t.Fatal("first answer came from the cache")
	}
	second, out := r.Respond(ctx, req)
	if !out.Cached || string(first) != string(second) {
		t.Fatal("second answer was not the cached first")
	}
	if err := f.records.Revoke(ctx, leaf.SerialNumber, store.ReasonSuperseded, time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	r.Invalidate()
	_, out = r.Respond(ctx, req)
	if out.Cached || out.Status != ocsp.Revoked {
		t.Fatalf("after revocation: %+v", out)
	}

	stranger := &x509.Certificate{SerialNumber: big.NewInt(424242), RawIssuer: f.inter.RawSubject}
	r.Respond(ctx, request(t, stranger, f.inter, crypto.SHA1))
	r.mu.Lock()
	_, cachedUnknown := r.cache["424242"]
	r.mu.Unlock()
	if cachedUnknown {
		t.Fatal("an unknown serial was cached; the cache would be bounded by a client's imagination")
	}
}

func TestDueForRenewal_HalfLife(t *testing.T) {
	f := newFixture(t)
	r := f.newResponder(t, 7*24*time.Hour, time.Hour)
	c := r.Certificate()
	if r.dueForRenewal(c.NotBefore.Add(time.Hour)) {
		t.Fatal("due an hour in")
	}
	if !r.dueForRenewal(c.NotBefore.Add(4 * 24 * time.Hour)) {
		t.Fatal("not due after four of seven days")
	}
}
