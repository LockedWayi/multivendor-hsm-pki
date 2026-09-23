package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
)

// csrWith builds a signed request with the given subject and names.
func csrWith(t *testing.T, subject pkix.Name, dns []string, ips []net.IP, uris []string) *x509.CertificateRequest {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var parsed []*url.URL
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		parsed = append(parsed, u)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subject, DNSNames: dns, IPAddresses: ips, URIs: parsed,
	}, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	return csr
}

// TestIssue_TemplateComesFromTheProfile is the sub-task's Done-when: the
// same request under two profiles yields certificates that differ in
// exactly the profile-controlled fields and in nothing else.
func TestIssue_TemplateComesFromTheProfile(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		// A request both tls-client and code-signing accept: CN and O in
		// the subject, a URI name, an EC key.
		csr := csrWith(t, pkix.Name{CommonName: "release signer", Organization: []string{"Example"}}, nil, nil, []string{"urn:hsm-pki:signer:release"})

		client, err := c.Issue(csr, withValidity("tls-client", 20*time.Minute))
		if err != nil {
			t.Fatalf("Issue(tls-client): %v", err)
		}
		signing, err := c.Issue(csr, withValidity("code-signing", 40*time.Minute))
		if err != nil {
			t.Fatalf("Issue(code-signing): %v", err)
		}

		// What the profile controls differs.
		if !reflect.DeepEqual(client.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
			t.Errorf("tls-client EKUs = %v, want clientAuth alone", client.ExtKeyUsage)
		}
		if !reflect.DeepEqual(signing.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}) {
			t.Errorf("code-signing EKUs = %v, want codeSigning alone", signing.ExtKeyUsage)
		}
		if got := signing.NotAfter.Sub(client.NotAfter).Round(time.Minute); got != 20*time.Minute {
			t.Errorf("validity difference = %s, want the profiles' 20 minutes", got)
		}
		// What the request controls is the same, filtered by the same
		// allow-lists.
		if client.Subject.String() != signing.Subject.String() || client.Subject.CommonName != "release signer" || client.Subject.Organization[0] != "Example" {
			t.Errorf("subjects differ or are wrong: %q vs %q", client.Subject, signing.Subject)
		}
		if len(client.URIs) != 1 || len(signing.URIs) != 1 || client.URIs[0].String() != signing.URIs[0].String() {
			t.Errorf("URIs differ: %v vs %v", client.URIs, signing.URIs)
		}
		if !client.PublicKey.(*ecdsa.PublicKey).Equal(signing.PublicKey) {
			t.Error("public keys differ")
		}
		// And what no profile controls is fixed policy on both.
		for _, cert := range []*x509.Certificate{client, signing} {
			if cert.IsCA || !cert.BasicConstraintsValid {
				t.Error("a leaf came out as a CA, or without basic constraints")
			}
			if len(cert.CRLDistributionPoints) != 1 || len(cert.IssuingCertificateURL) != 1 {
				t.Error("distribution pointers missing")
			}
		}
	})
}

// TestIssue_EachBuiltinCarriesExactlyItsUsages: no EKU or KU beyond the
// profile's, and the responder's nocheck extension is present only there.
func TestIssue_EachBuiltinCarriesExactlyItsUsages(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		cases := []struct {
			profile string
			csr     *x509.CertificateRequest
			eku     []x509.ExtKeyUsage
			ku      x509.KeyUsage
			nocheck bool
		}{
			{"tls-server", csrWith(t, pkix.Name{CommonName: "pki.example.test"}, []string{"pki.example.test"}, nil, nil),
				[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageDigitalSignature, false},
			{"tls-client", csrWith(t, pkix.Name{CommonName: "alice"}, nil, nil, nil),
				[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, x509.KeyUsageDigitalSignature, false},
			{"code-signing", csrWith(t, pkix.Name{CommonName: "release"}, nil, nil, nil),
				[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, x509.KeyUsageDigitalSignature, false},
			{"ocsp-responder", csrWith(t, pkix.Name{CommonName: "ocsp"}, nil, nil, nil),
				[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, x509.KeyUsageDigitalSignature, true},
		}
		for _, tc := range cases {
			t.Run(tc.profile, func(t *testing.T) {
				cert, err := c.Issue(tc.csr, withValidity(tc.profile, 30*time.Minute))
				if err != nil {
					t.Fatalf("Issue: %v", err)
				}
				if !reflect.DeepEqual(cert.ExtKeyUsage, tc.eku) {
					t.Errorf("EKUs = %v, want %v", cert.ExtKeyUsage, tc.eku)
				}
				if len(cert.UnknownExtKeyUsage) != 0 {
					t.Errorf("unknown EKUs present: %v", cert.UnknownExtKeyUsage)
				}
				// An EC key: keyEncipherment is dropped even where the
				// profile lists it.
				if cert.KeyUsage != tc.ku {
					t.Errorf("KU = %v, want %v", cert.KeyUsage, tc.ku)
				}
				found := false
				for _, ext := range cert.Extensions {
					if ext.Id.Equal(profile.OIDOCSPNoCheck) {
						found = true
					}
				}
				if found != tc.nocheck {
					t.Errorf("id-pkix-ocsp-nocheck present = %t, want %t", found, tc.nocheck)
				}
			})
		}
	})
}

// TestIssue_RSAKeepsKeyEnciphermentOnlyWherePermitted: the RSA-only key
// usage follows the profile, not the key alone.
func TestIssue_RSAKeepsKeyEnciphermentOnlyWherePermitted(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		client, err := c.Issue(signedCSR(t, rsaKey, pkix.Name{CommonName: "rsa"}), tlsClient())
		if err != nil {
			t.Fatalf("Issue(tls-client): %v", err)
		}
		if client.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			t.Error("RSA under tls-client lost keyEncipherment, which the profile lists")
		}
		signing, err := c.Issue(signedCSR(t, rsaKey, pkix.Name{CommonName: "rsa"}), withValidity("code-signing", 30*time.Minute))
		if err != nil {
			t.Fatalf("Issue(code-signing): %v", err)
		}
		if signing.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			t.Error("RSA under code-signing gained keyEncipherment, which the profile does not list")
		}
	})
}

// TestIssue_PolicyRefusals: each policy rule, one request that breaks
// only it, and the sentinel the HTTP layer maps to a 4xx.
func TestIssue_PolicyRefusals(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		cases := []struct {
			name    string
			profile *profile.Profile
			csr     *x509.CertificateRequest
			want    error
		}{
			{"tls-server with no name", tlsServer(),
				csrWith(t, pkix.Name{CommonName: "pki.example.test"}, nil, nil, nil), ca.ErrNameNotAllowed},
			{"tls-server with a URI name it does not copy", tlsServer(),
				csrWith(t, pkix.Name{CommonName: "pki"}, []string{"pki.example.test"}, nil, []string{"urn:x"}), ca.ErrNameNotAllowed},
			{"tls-client with a DNS name", tlsClient(),
				csrWith(t, pkix.Name{CommonName: "alice"}, []string{"alice.example.test"}, nil, nil), ca.ErrNameNotAllowed},
			{"tls-server with an organisation in the subject", tlsServer(),
				csrWith(t, pkix.Name{CommonName: "pki", Organization: []string{"Example"}}, []string{"pki.example.test"}, nil, nil), ca.ErrSubjectNotAllowed},
			{"a country nobody allows", tlsClient(),
				csrWith(t, pkix.Name{CommonName: "alice", Country: []string{"TR"}}, nil, nil, nil), ca.ErrSubjectNotAllowed},
			{"a key algorithm the profile does not accept", func() *profile.Profile {
				p := tlsClient()
				p.KeyAlgorithms = []profile.KeyAlgorithm{profile.KeyECP256}
				return p
			}(), signedCSR(t, p384, pkix.Name{CommonName: "alice"}), ca.ErrDisallowedKeyType},
			{"a profile above the CA's ceiling", withValidity("tls-client", 48*time.Hour),
				csrWith(t, pkix.Name{CommonName: "alice"}, nil, nil, nil), ca.ErrValidityExceedsPolicy},
			{"no profile at all", nil,
				csrWith(t, pkix.Name{CommonName: "alice"}, nil, nil, nil), profile.ErrUnknownProfile},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cert, err := c.Issue(tc.csr, tc.profile)
				if !errors.Is(err, tc.want) {
					t.Fatalf("Issue = (%v, %v), want %v", cert != nil, err, tc.want)
				}
			})
		}
	})
}

// TestIssue_SubjectIsFilteredNotCopied: the certificate carries the
// attributes the profile lists and the request's values for them, so
// the allow-list is what the relying party sees, not a check that was
// passed and then forgotten.
func TestIssue_SubjectIsFilteredNotCopied(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		csr := csrWith(t, pkix.Name{CommonName: "alice", Organization: []string{"Example"}, OrganizationalUnit: []string{"Ops"}}, nil, nil, nil)
		cert, err := c.Issue(csr, tlsClient())
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if cert.Subject.CommonName != "alice" || cert.Subject.Organization[0] != "Example" || cert.Subject.OrganizationalUnit[0] != "Ops" {
			t.Fatalf("subject = %q, want CN, O and OU as requested", cert.Subject)
		}
		if len(cert.Subject.Country) != 0 || len(cert.Subject.Locality) != 0 {
			t.Fatalf("subject = %q carries attributes the request never asked for", cert.Subject)
		}
	})
}
