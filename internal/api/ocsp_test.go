package api_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
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

	"golang.org/x/crypto/ocsp"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/responder"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

// ocspServers starts both surfaces with a responder whose key is on the
// intermediate's token, the way the service runs it: the key is
// generated there, the signer is HSM-backed, and the responder issues
// its own certificate through the CA at construction.
func ocspServers(t *testing.T, b *hsmtest.Backend, window time.Duration) (*testServers, *responder.Responder, *store.Memory) {
	t.Helper()
	c, adapter, ws, rootArtifacts := newTestCA(t, b)
	records := store.NewMemory()
	ctx := context.Background()

	keyLabel := b.Label("ocsp-signing-key-v1")
	session, err := adapter.OpenSession(ctx, ws, pk11.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if _, err := adapter.GenerateKeyPair(ctx, session, pk11.KeyPairRequest{Curve: pk11.P256, Label: keyLabel, Sign: true, Verify: true}); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_ = adapter.CloseSession(ctx, session)
	signer, err := ca.NewSigner(ctx, adapter, ws, pk11.SessionOptions{}, keyLabel, pk11.P256)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	p := profile.Builtin()[profile.InternalOnlyProfile]
	p.Validity = 30 * time.Minute
	resp, err := responder.New(ctx, responder.Config{
		Issuer: c, Records: records, Signer: signer, Profile: p, Validity: window, Logger: testLogger(),
	})
	if err != nil {
		t.Fatalf("responder.New: %v", err)
	}
	ts := startServersFull(t, httptest.NewUnstartedServer(nil), c, adapter, ws, records, 24*time.Hour, rootArtifacts,
		api.Authorization{Issuers: entitled(testIssuer), Revokers: []string{testIssuer}}, resp)
	// The responder's own certificate is a record too.
	ts.seeded++
	return ts, resp, records
}

func ocspRequest(t *testing.T, leaf, issuer *x509.Certificate) []byte {
	t.Helper()
	der, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	return der
}

// postOCSP and getOCSP are the two RFC 6960 transports.
func postOCSP(t *testing.T, ts *testServers, req []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(ts.public.URL+api.OCSPPath, api.ContentTypeOCSPRequest, bytes.NewReader(req))
	if err != nil {
		t.Fatalf("POST /ocsp: %v", err)
	}
	return resp
}

func getOCSP(t *testing.T, ts *testServers, req []byte) *http.Response {
	t.Helper()
	resp, err := http.Get(ts.public.URL + api.OCSPPath + "/" + base64.StdEncoding.EncodeToString(req))
	if err != nil {
		t.Fatalf("GET /ocsp/...: %v", err)
	}
	return resp
}

func readOCSP(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != api.ContentTypeOCSPResponse {
		t.Fatalf("Content-Type = %q", ct)
	}
	return body
}

// TestOCSP_GoodRevokedUnknownOverBothTransports: the service's responder,
// signing through the token, answers the three statuses over POST and
// GET, and a revocation is visible at once rather than at nextUpdate.
func TestOCSP_GoodRevokedUnknownOverBothTransports(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ts, _, _ := ocspServers(t, b, time.Hour)
		defer ts.Close()
		leaf := issueTestCert(t, ts, "ocsp.example.test")
		issuer := ts.ca.Certificate()
		req := ocspRequest(t, leaf, issuer)

		for name, fetch := range map[string]func() *http.Response{
			"POST": func() *http.Response { return postOCSP(t, ts, req) },
			"GET":  func() *http.Response { return getOCSP(t, ts, req) },
		} {
			resp := fetch()
			cc := resp.Header.Get("Cache-Control")
			body := readOCSP(t, resp)
			parsed, err := ocsp.ParseResponseForCert(body, leaf, issuer)
			if err != nil {
				t.Fatalf("%s: ParseResponseForCert: %v", name, err)
			}
			if parsed.Status != ocsp.Good {
				t.Fatalf("%s: status = %d, want good", name, parsed.Status)
			}
			if !strings.Contains(cc, "max-age=") || !strings.Contains(cc, "must-revalidate") {
				t.Fatalf("%s: Cache-Control = %q", name, cc)
			}
		}

		// Revoke over the authenticated surface: the CRL cache and the
		// responder cache both drop, and the next answer is revoked.
		r := revokeTestCert(t, ts, leaf.SerialNumber)
		r.Body.Close()
		parsed, err := ocsp.ParseResponseForCert(readOCSP(t, postOCSP(t, ts, req)), leaf, issuer)
		if err != nil {
			t.Fatalf("after revoke: %v", err)
		}
		if parsed.Status != ocsp.Revoked {
			t.Fatalf("after revoke: status = %d, want revoked", parsed.Status)
		}

		// A serial this CA never issued is unknown, never good.
		stranger := &x509.Certificate{SerialNumber: big.NewInt(31337), RawIssuer: issuer.RawSubject}
		parsed, err = ocsp.ParseResponse(readOCSP(t, postOCSP(t, ts, ocspRequest(t, stranger, issuer))), issuer)
		if err != nil {
			t.Fatalf("unknown: %v", err)
		}
		if parsed.Status != ocsp.Unknown {
			t.Fatalf("unknown: status = %d", parsed.Status)
		}
	})
}

// TestOCSP_ErrorsAreOCSPResponsesNotHTTPErrors: a malformed request and
// a request about another issuer are answered with the RFC 6960 error
// response, HTTP 200, and no cache lifetime.
func TestOCSP_ErrorsAreOCSPResponsesNotHTTPErrors(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ts, _, _ := ocspServers(t, b, time.Hour)
		defer ts.Close()

		status := func(resp *http.Response) ocsp.ResponseStatus {
			t.Helper()
			if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
				t.Fatalf("Cache-Control on an error response = %q, want no-store", cc)
			}
			_, err := ocsp.ParseResponse(readOCSP(t, resp), nil)
			var re ocsp.ResponseError
			if !errors.As(err, &re) {
				t.Fatalf("not an OCSP error response: %v", err)
			}
			return re.Status
		}
		if got := status(postOCSP(t, ts, []byte("garbage"))); got != ocsp.Malformed {
			t.Fatalf("garbage POST: %v", got)
		}
		garbageGet, _ := http.Get(ts.public.URL + api.OCSPPath + "/not%20base64!!")
		if got := status(garbageGet); got != ocsp.Malformed {
			t.Fatalf("garbage GET: %v", got)
		}
		leaf := issueTestCert(t, ts, "other.example.test")
		if got := status(postOCSP(t, ts, ocspRequest(t, leaf, ts.root))); got != ocsp.Unauthorized {
			t.Fatalf("other issuer: %v", got)
		}
	})
}

// TestOCSP_AbsentWithoutAResponder: no responder means no route, and a
// leaf issued by that service carries no OCSP pointer.
func TestOCSP_AbsentWithoutAResponder(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		ts := startServers(t, c, adapter, ws, store.NewMemory(), 24*time.Hour, rootArtifacts)
		defer ts.Close()
		resp, err := http.Post(ts.public.URL+api.OCSPPath, api.ContentTypeOCSPRequest, bytes.NewReader([]byte{0x30}))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		expectStatus(t, resp, http.StatusNotFound, "POST /ocsp with no responder")
		leaf := issueTestCert(t, ts, "no-ocsp.example.test")
		if len(leaf.OCSPServer) != 0 {
			t.Fatalf("OCSPServer = %v on a service with no responder", leaf.OCSPServer)
		}
	})
}

// TestOCSP_OpenSSLAgrees is the interop check: openssl ocsp, the client a
// relying party actually runs, verifies the response chain and reads
// good, then revoked, then unknown for a serial this CA never issued.
func TestOCSP_OpenSSLAgrees(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not on PATH")
	}
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ts, _, _ := ocspServers(t, b, time.Hour)
		defer ts.Close()
		leaf := issueTestCert(t, ts, "openssl-ocsp.example.test")

		dir := t.TempDir()
		write := func(name string, der []byte) string {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			return path
		}
		rootPath := write("root.pem", ts.root.Raw)
		interPath := write("intermediate.pem", ts.ca.Certificate().Raw)
		leafPath := write("leaf.pem", leaf.Raw)
		url := ts.public.URL + api.OCSPPath

		// -no_nonce: this responder follows RFC 5019's lightweight
		// profile and does not echo nonces, which openssl would otherwise
		// warn about. The responder certificate travels in the response;
		// -verify_other supplies the intermediate it chains through to
		// the root in -CAfile.
		ask := func(extra ...string) string {
			t.Helper()
			args := append([]string{"ocsp", "-no_nonce", "-CAfile", rootPath, "-verify_other", interPath, "-issuer", interPath, "-url", url}, extra...)
			out, err := exec.Command(openssl, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("openssl %v: %v: %s", args, err, out)
			}
			if !strings.Contains(string(out), "Response verify OK") {
				t.Fatalf("openssl did not verify the response: %s", out)
			}
			return string(out)
		}
		if out := ask("-cert", leafPath); !strings.Contains(out, "leaf.pem: good") {
			t.Fatalf("want good: %s", out)
		}
		r := revokeTestCert(t, ts, leaf.SerialNumber)
		r.Body.Close()
		if out := ask("-cert", leafPath); !strings.Contains(out, "leaf.pem: revoked") {
			t.Fatalf("want revoked: %s", out)
		}
		if out := ask("-serial", "0x"+strings.ToUpper(big.NewInt(31337).Text(16))); !strings.Contains(out, ": unknown") {
			t.Fatalf("want unknown: %s", out)
		}
	})
}

// TestOCSP_IssuedLeavesNameTheResponder: with a responder configured the
// distribution carries its URL and a leaf issued through the API points
// at it.
func TestOCSP_IssuedLeavesNameTheResponder(t *testing.T) {
	d := api.LeafDistributionWithOCSP("https://pki.example.test/")
	if d.OCSPURL != "https://pki.example.test"+api.OCSPPath || d.CRLURL != "https://pki.example.test"+api.CRLPath {
		t.Fatalf("LeafDistributionWithOCSP = %+v", d)
	}
	if api.LeafDistributionFor("https://pki.example.test").OCSPURL != "" {
		t.Fatal("LeafDistributionFor names a responder")
	}
}
