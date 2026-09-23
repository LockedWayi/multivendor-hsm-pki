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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/entitlement"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

const (
	aliceID = "urn:hsm-pki:operator:alice"
	bobID   = "urn:hsm-pki:operator:bob"
	carolID = "urn:hsm-pki:operator:carol"
)

// policyServers starts the two surfaces under a mapping where alice may
// issue tls-server certificates under example.test, bob may issue
// tls-client certificates for his own team, and carol, a valid recorded
// client, is bound to nothing. Each returns an authenticated client.
func policyServers(t *testing.T, b *hsmtest.Backend) (ts *testServers, alice, bob, carol *http.Client, records *store.Memory) {
	t.Helper()
	c, adapter, ws, rootArtifacts := newTestCA(t, b)
	records = store.NewMemory()
	authz := api.Authorization{
		Issuers: mustEntitlements(t, map[string]entitlement.Spec{
			aliceID: {Profiles: []string{"tls-server"}, Names: []string{"cn:*.example.test", "dns:*.example.test"}},
			bobID:   {Profiles: []string{"tls-client"}, Names: []string{"cn:*", "uri:urn:hsm-pki:team-b:*"}},
		}),
		Revokers: []string{aliceID},
	}
	ts = startServersOn(t, httptest.NewUnstartedServer(nil), c, adapter, ws, records, 24*time.Hour, rootArtifacts, authz)
	// startServersOn seeded testIssuer; the three below are seeded too.
	alice = ts.clientWith(t, issueClientCertificate(t, c, records, aliceID))
	bob = ts.clientWith(t, issueClientCertificate(t, c, records, bobID))
	carol = ts.clientWith(t, issueClientCertificate(t, c, records, carolID))
	ts.seeded += 3
	return ts, alice, bob, carol, records
}

// request posts a CSR with the given subject and names under profile.
func request(t *testing.T, client *http.Client, ts *testServers, profile, cn string, dns []string, uris []string, emails ...string) *http.Response {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns, EmailAddresses: emails}
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	resp, err := client.Post(ts.tls.URL+"/certificates?profile="+profile, "application/x-pem-file", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /certificates?profile=%s: %v", profile, err)
	}
	return resp
}

// expectDenied reads and closes resp and fails unless it is a 403 whose
// body is the fixed message, with nothing about the policy in it, and
// unless the store still holds exactly seeded records.
func expectDenied(t *testing.T, resp *http.Response, records *store.Memory, seeded int, context string) {
	t.Helper()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("%s: status = %d, want 403; body: %s", context, resp.StatusCode, body)
	}
	for _, leak := range []string{"example.test", "tls-server", "tls-client", "pattern", "urn:hsm-pki"} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("%s: the refusal echoes policy detail %q: %s", context, leak, body)
		}
	}
	if records.Len() != seeded {
		t.Fatalf("%s: store holds %d records, want %d: a denied request was recorded", context, records.Len(), seeded)
	}
}

// TestIssuancePolicy_EntitledRequestSucceeds: alice, inside her profile
// and her names, is issued to and recorded.
func TestIssuancePolicy_EntitledRequestSucceeds(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ts, alice, _, _, records := policyServers(t, b)
		defer ts.Close()
		resp := request(t, alice, ts, "tls-server", "www.example.test", []string{"www.example.test", "api.example.test"}, nil)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body: %s", resp.StatusCode, body)
		}
		if records.Len() != ts.seeded+1 {
			t.Fatalf("store holds %d records, want %d", records.Len(), ts.seeded+1)
		}
	})
}

// TestIssuancePolicy_CrossIdentityDenied: the request alice may make is
// refused to bob, who is entitled to a different profile, and bob's own
// kind of request is refused to alice. Same request, different identity,
// 403, nothing recorded, nothing said.
func TestIssuancePolicy_CrossIdentityDenied(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ts, alice, bob, _, records := policyServers(t, b)
		defer ts.Close()
		expectDenied(t, request(t, bob, ts, "tls-server", "www.example.test", []string{"www.example.test"}, nil), records, ts.seeded, "bob asking for alice's profile")
		expectDenied(t, request(t, alice, ts, "tls-client", "someone", nil, []string{"urn:hsm-pki:team-b:x"}), records, ts.seeded, "alice asking for bob's profile")
	})
}

// TestIssuancePolicy_NoBindingDenied: carol chains to the root, is in
// the store, and is bound to nothing. She issues nothing.
func TestIssuancePolicy_NoBindingDenied(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ts, _, _, carol, records := policyServers(t, b)
		defer ts.Close()
		for _, profile := range []string{"tls-server", "tls-client", "code-signing"} {
			expectDenied(t, request(t, carol, ts, profile, "www.example.test", []string{"www.example.test"}, nil), records, ts.seeded, "carol under "+profile)
		}
	})
}

// TestIssuancePolicy_NameOutsideThePatternDenied: alice's profile is
// right and one name is not hers. The whole request is refused; a
// certificate is not issued with the name dropped.
func TestIssuancePolicy_NameOutsideThePatternDenied(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ts, alice, bob, _, records := policyServers(t, b)
		defer ts.Close()
		expectDenied(t, request(t, alice, ts, "tls-server", "www.example.test", []string{"www.example.test", "login.bank.test"}, nil), records, ts.seeded, "alice naming a host outside example.test")
		expectDenied(t, request(t, alice, ts, "tls-server", "www.evil.test", []string{"www.example.test"}, nil), records, ts.seeded, "alice with a CN outside example.test")
		// bob may not name alice: the URI pattern is his team's.
		expectDenied(t, request(t, bob, ts, "tls-client", "impostor", nil, []string{aliceID}), records, ts.seeded, "bob naming alice's identity")
		// A type with no pattern at all is refused, even for a name the
		// profile would otherwise copy.
		expectDenied(t, request(t, bob, ts, "tls-client", "bob", nil, []string{"urn:hsm-pki:team-b:x"}, "someone@example.test"), records, ts.seeded, "bob with an email, a type he has no pattern for")
	})
}

// TestIssuancePolicy_InternalProfileIsNeverGranted: the parser refuses a
// grant of ocsp-responder, and a client holding every grant a client can
// hold is still refused it at the point of use, with nothing recorded.
// The forged-entitlement case is in the entitlement package's own tests.
func TestIssuancePolicy_InternalProfileIsNeverGranted(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		if _, err := entitlement.Parse(map[string]entitlement.Spec{aliceID: {Profiles: []string{"ocsp-responder"}, Names: []string{"cn:*"}}}); err == nil {
			t.Fatal("Parse accepted a grant of the internal-only profile")
		}
		ts := startServersOn(t, httptest.NewUnstartedServer(nil), c, adapter, ws, records, 24*time.Hour, rootArtifacts,
			api.Authorization{Issuers: entitled(aliceID), Revokers: []string{aliceID}})
		defer ts.Close()
		alice := ts.clientWith(t, issueClientCertificate(t, c, records, aliceID))
		ts.seeded++
		expectDenied(t, request(t, alice, ts, "ocsp-responder", "ocsp", nil, nil), records, ts.seeded, "a client asking for ocsp-responder")
	})
}
