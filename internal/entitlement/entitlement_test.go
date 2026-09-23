package entitlement

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
)

func mustPattern(t *testing.T, s string) Pattern {
	t.Helper()
	p, err := ParsePattern(s)
	if err != nil {
		t.Fatalf("ParsePattern(%q): %v", s, err)
	}
	return p
}

// TestPattern_GlobSemantics pins what * means for each type and that DNS
// alone folds case.
func TestPattern_GlobSemantics(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"dns:*.example.test", "a.example.test", true},
		{"dns:*.example.test", "a.b.example.test", true},
		{"dns:*.example.test", "example.test", false},
		{"dns:*.example.test", "a.example.test.evil", false},
		{"dns:*.example.test", "A.EXAMPLE.TEST", true},
		{"dns:*", "anything.at.all", true},
		{"dns:localhost", "localhost", true},
		{"dns:localhost", "localhost2", false},
		{"cn:alice", "alice", true},
		{"cn:alice", "Alice", false},
		{"cn:*", "", true},
		{"uri:urn:hsm-pki:operator:*", "urn:hsm-pki:operator:alice", true},
		{"uri:urn:hsm-pki:operator:*", "urn:hsm-pki:signer:release", false},
		{"uri:https://example.test/*", "https://example.test/a/b", true},
		{"uri:https://example.test/*", "https://example.test.evil/a", false},
		{"email:*@example.test", "alice@example.test", true},
		{"email:*@example.test", "alice@example.test.evil", false},
		{"ip:10.0.0.1", "10.0.0.1", true},
		{"ip:10.0.0.1", "10.0.0.2", false},
		{"ip:10.0.0.0/8", "10.200.1.1", true},
		{"ip:10.0.0.0/8", "11.0.0.1", false},
		{"ip:*", "::1", true},
		{"ip:::1", "::1", true},
	}
	for _, tc := range cases {
		if got := mustPattern(t, tc.pattern).matches(tc.name); got != tc.want {
			t.Errorf("%q matches %q = %t, want %t", tc.pattern, tc.name, got, tc.want)
		}
	}
	// A regexp metacharacter in the glob is a literal, not a regexp.
	if mustPattern(t, "cn:a.b").matches("aXb") {
		t.Error("the dot in cn:a.b matched any character; the glob leaked into a regexp")
	}
}

func TestParsePattern_Refusals(t *testing.T) {
	for _, s := range []string{"", "alice", "dns:", "host:example.test", "ip:not-an-ip", "ip:10.0.0.0/33", "DNS:example.test"} {
		if _, err := ParsePattern(s); err == nil {
			t.Errorf("ParsePattern(%q) succeeded", s)
		}
	}
}

func csr(cn string, dns []string, ips []net.IP, uris []string, emails []string) *x509.CertificateRequest {
	var parsed []*url.URL
	for _, raw := range uris {
		u, _ := url.Parse(raw)
		parsed = append(parsed, u)
	}
	return &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns, IPAddresses: ips, URIs: parsed, EmailAddresses: emails}
}

// TestEntitlement_PermitsNames: every name in the request needs a
// pattern of its type; a type with no pattern is refused outright.
func TestEntitlement_PermitsNames(t *testing.T) {
	e, err := Spec{Profiles: []string{"tls-server"}, Names: []string{"cn:*.example.test", "dns:*.example.test", "ip:10.0.0.0/8"}}.Compile("alice")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cases := []struct {
		name string
		csr  *x509.CertificateRequest
		ok   bool
	}{
		{"everything inside", csr("a.example.test", []string{"a.example.test", "b.example.test"}, []net.IP{net.IPv4(10, 1, 2, 3)}, nil, nil), true},
		{"no names at all", csr("", nil, nil, nil, nil), true},
		{"a DNS name outside", csr("a.example.test", []string{"a.example.test", "evil.test"}, nil, nil, nil), false},
		{"a CN outside", csr("evil", []string{"a.example.test"}, nil, nil, nil), false},
		{"an IP outside the range", csr("", nil, []net.IP{net.IPv4(11, 0, 0, 1)}, nil, nil), false},
		{"a URI, a type with no pattern", csr("", nil, nil, []string{"urn:x"}, nil), false},
		{"an email, a type with no pattern", csr("", nil, nil, nil, []string{"a@example.test"}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := e.PermitsNames(tc.csr)
			if tc.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrNotEntitled) {
				t.Fatalf("err = %v, want ErrNotEntitled", err)
			}
		})
	}
}

// TestSpec_Compile_Refusals: an entry that grants nothing, the
// internal-only profile, a duplicate, an empty name, a bad pattern.
func TestSpec_Compile_Refusals(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		want string
	}{
		{"no profiles", Spec{Names: []string{"cn:*"}}, "lists no profile"},
		{"no names", Spec{Profiles: []string{"tls-client"}}, "lists no name pattern"},
		{"the internal-only profile", Spec{Profiles: []string{"tls-client", "ocsp-responder"}, Names: []string{"cn:*"}}, "no client may obtain"},
		{"a profile twice", Spec{Profiles: []string{"tls-client", "tls-client"}, Names: []string{"cn:*"}}, "twice"},
		{"an empty profile name", Spec{Profiles: []string{""}, Names: []string{"cn:*"}}, "empty profile name"},
		{"a bad pattern", Spec{Profiles: []string{"tls-client"}, Names: []string{"host:*"}}, "unknown name type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.spec.Compile("alice")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Compile = %v, want it to say %q", err, tc.want)
			}
		})
	}
	if _, err := Parse(map[string]Spec{" ": {Profiles: []string{"tls-client"}, Names: []string{"cn:*"}}}); err == nil {
		t.Error("a blank identity was accepted")
	}
}

// TestEntitlement_PermitsProfile: granted means listed, and the
// internal-only profile is refused at the point of use even if an entry
// somehow carried it.
func TestEntitlement_PermitsProfile(t *testing.T) {
	e, err := Spec{Profiles: []string{"tls-client"}, Names: []string{"cn:*"}}.Compile("alice")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !e.PermitsProfile("tls-client") || e.PermitsProfile("tls-server") || e.PermitsProfile("") {
		t.Fatalf("PermitsProfile: %v", e.Profiles())
	}
	forged := Entitlement{profiles: map[string]bool{"ocsp-responder": true}}
	if forged.PermitsProfile("ocsp-responder") {
		t.Fatal("the internal-only profile was permitted at the point of use")
	}
	if got := (Map{"b": e, "a": e}).Identities(); strings.Join(got, ",") != "a,b" {
		t.Fatalf("Identities = %v", got)
	}
}
