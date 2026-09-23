package profile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestBuiltin_EveryProfileIsValid: the four the platform ships with must
// pass the same validation a configured set does, under a ceiling of a
// year, which is what config.example.yaml sets.
func TestBuiltin_EveryProfileIsValid(t *testing.T) {
	set := Builtin()
	if err := set.Validate(365 * 24 * time.Hour); err != nil {
		t.Fatalf("Builtin().Validate: %v", err)
	}
	for _, name := range []string{"tls-server", "tls-client", "code-signing", "ocsp-responder"} {
		if _, err := set.Lookup(name); err != nil {
			t.Errorf("Lookup(%q): %v", name, err)
		}
	}
	// A fresh set each call, so adjusting one does not change the next.
	set["tls-client"].Validity = time.Hour
	if got := Builtin()["tls-client"].Validity; got == time.Hour {
		t.Fatal("Builtin() handed back the same Profile it handed out before")
	}
}

// TestBuiltin_ShapesThePlatformDependsOn pins the properties other
// packages rely on rather than re-derive: the service's own loader wants
// serverAuth on the identity, the TLS client check wants clientAuth, the
// responder wants nocheck.
func TestBuiltin_ShapesThePlatformDependsOn(t *testing.T) {
	set := Builtin()
	has := func(p *Profile, eku x509.ExtKeyUsage) bool {
		for _, e := range p.ExtKeyUsages {
			if e == eku {
				return true
			}
		}
		return false
	}
	if p := set["tls-server"]; !has(p, x509.ExtKeyUsageServerAuth) || has(p, x509.ExtKeyUsageClientAuth) || !p.SANRequired {
		t.Errorf("tls-server = %+v, want serverAuth only and a SAN required", p)
	}
	if p := set["tls-client"]; !has(p, x509.ExtKeyUsageClientAuth) || has(p, x509.ExtKeyUsageServerAuth) || p.SANRequired {
		t.Errorf("tls-client = %+v, want clientAuth only and no SAN required", p)
	}
	if p := set["code-signing"]; !has(p, x509.ExtKeyUsageCodeSigning) || len(p.ExtKeyUsages) != 1 {
		t.Errorf("code-signing = %+v, want codeSigning alone", p)
	}
	if p := set["ocsp-responder"]; !has(p, x509.ExtKeyUsageOCSPSigning) || !p.OCSPNoCheck || p.Validity > 30*24*time.Hour {
		t.Errorf("ocsp-responder = %+v, want ocspSigning, nocheck, and a short life", p)
	}
}

func TestLookup_NoDefault(t *testing.T) {
	set := Builtin()
	for _, name := range []string{"", "default", "TLS-SERVER", "tls-server "} {
		if _, err := set.Lookup(name); !errors.Is(err, ErrUnknownProfile) {
			t.Errorf("Lookup(%q) = %v, want ErrUnknownProfile", name, err)
		}
	}
}

// TestValidate_Refusals: each rule, one profile that breaks only it.
func TestValidate_Refusals(t *testing.T) {
	good := func() *Profile {
		return &Profile{
			Name:          "p",
			ExtKeyUsages:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:      x509.KeyUsageDigitalSignature,
			SubjectRDNs:   []string{"CN"},
			KeyAlgorithms: []KeyAlgorithm{KeyECP256},
			Validity:      time.Hour,
		}
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("the baseline profile is refused: %v", err)
	}
	cases := []struct {
		name  string
		mut   func(*Profile)
		want  string
		limit time.Duration
	}{
		{"no extended key usage", func(p *Profile) { p.ExtKeyUsages = nil }, "no extended key usage", 0},
		{"no key usage", func(p *Profile) { p.KeyUsage = 0 }, "no key usage", 0},
		{"keyCertSign on a leaf", func(p *Profile) { p.KeyUsage |= x509.KeyUsageCertSign }, "keyCertSign", 0},
		{"cRLSign on a leaf", func(p *Profile) { p.KeyUsage |= x509.KeyUsageCRLSign }, "cRLSign", 0},
		{"zero validity", func(p *Profile) { p.Validity = 0 }, "validity must be positive", 0},
		{"no key algorithm", func(p *Profile) { p.KeyAlgorithms = nil }, "no key algorithm", 0},
		{"SAN required but none allowed", func(p *Profile) { p.SANRequired = true }, "allows no type", 0},
		{"nothing to name", func(p *Profile) { p.SubjectRDNs = nil }, "names nothing", 0},
		{"unknown subject attribute", func(p *Profile) { p.SubjectRDNs = []string{"CN", "EMAIL"} }, "is not one of", 0},
		{"over the ceiling", func(p *Profile) {}, "exceeds the CA's ceiling", time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := good()
			tc.mut(p)
			err := Set{"p": p}.Validate(tc.limit)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want it to say %q", err, tc.want)
			}
		})
	}
	if err := (Set{}).Validate(0); err == nil {
		t.Fatal("an empty set was accepted")
	}
	renamed := good()
	if err := (Set{"other": renamed}).Validate(0); err == nil {
		t.Fatal("a profile stored under a name it does not carry was accepted")
	}
}

func TestAllowsKey(t *testing.T) {
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := &Profile{Name: "p", KeyAlgorithms: []KeyAlgorithm{KeyECP256, KeyRSA}}
	if err := p.AllowsKey(&ec256.PublicKey); err != nil {
		t.Errorf("P-256 refused: %v", err)
	}
	if err := p.AllowsKey(&rsa2048.PublicKey); err != nil {
		t.Errorf("RSA-2048 refused: %v", err)
	}
	if err := p.AllowsKey(&ec384.PublicKey); err == nil {
		t.Error("P-384 accepted by a profile that lists only P-256 and RSA")
	}
	if err := p.AllowsKey(&rsa.PublicKey{N: rsa2048.N.Rsh(rsa2048.N, 1024), E: 65537}); err == nil {
		t.Error("a 1024-bit RSA key was accepted")
	}
	if err := p.AllowsKey("not a key"); err == nil {
		t.Error("a non-key was accepted")
	}
}

func TestCheckSANs(t *testing.T) {
	u, _ := url.Parse("urn:hsm-pki:operator:alice")
	server := &Profile{Name: "s", SANTypes: []SANType{SANDNS, SANIP}, SANRequired: true}
	client := &Profile{Name: "c", SANTypes: []SANType{SANURI}}

	if err := server.CheckSANs(&x509.CertificateRequest{DNSNames: []string{"a.example.test"}}); err != nil {
		t.Errorf("a DNS name under tls-server refused: %v", err)
	}
	if err := server.CheckSANs(&x509.CertificateRequest{IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)}}); err != nil {
		t.Errorf("an IP under tls-server refused: %v", err)
	}
	if err := server.CheckSANs(&x509.CertificateRequest{}); err == nil {
		t.Error("tls-server accepted a request with no name")
	}
	if err := server.CheckSANs(&x509.CertificateRequest{DNSNames: []string{"a"}, URIs: []*url.URL{u}}); err == nil {
		t.Error("tls-server accepted a URI name it does not copy; a caller who asked for a name they will not get should be refused, not trimmed")
	}
	if err := client.CheckSANs(&x509.CertificateRequest{}); err != nil {
		t.Errorf("tls-client refused a request with no name: %v", err)
	}
	if err := client.CheckSANs(&x509.CertificateRequest{URIs: []*url.URL{u}}); err != nil {
		t.Errorf("a URI under tls-client refused: %v", err)
	}
	if err := client.CheckSANs(&x509.CertificateRequest{EmailAddresses: []string{"a@example.test"}}); err == nil {
		t.Error("tls-client with uri only accepted an email name")
	}
}

// TestSubject: the subject is filtered, not copied. An attribute the
// profile does not list is refused; a request whose subject reduces to
// nothing is refused unless a SAN carries the name instead.
func TestSubject(t *testing.T) {
	requested := pkix.Name{CommonName: "alice", Organization: []string{"Example"}, Country: []string{"TR"}}
	// pkix.Name.Names is only populated by parsing, so build it the way
	// a parsed request arrives.
	var parsed pkix.Name
	parsed.FillFromRDNSequence(&pkix.RDNSequence{requested.ToRDNSequence()[0]})
	parsed.Names = flatten(requested.ToRDNSequence())

	cnOnly := &Profile{Name: "p", SubjectRDNs: []string{"CN"}}
	if _, err := cnOnly.Subject(parsed); err == nil {
		t.Error("a profile copying CN accepted a request carrying O and C")
	}
	cnO := &Profile{Name: "p", SubjectRDNs: []string{"CN", "O", "C"}}
	got, err := cnO.Subject(parsed)
	if err != nil {
		t.Fatalf("Subject: %v", err)
	}
	if got.CommonName != "alice" || len(got.Organization) != 1 || got.Organization[0] != "Example" || got.Country[0] != "TR" {
		t.Fatalf("Subject = %+v, want CN, O and C copied", got)
	}

	// An attribute this CA has no name for is refused whatever the list.
	var odd pkix.Name
	odd.Names = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: "serial"}}
	if _, err := cnO.Subject(odd); err == nil {
		t.Error("serialNumber (2.5.4.5) was accepted; it is not in the vocabulary")
	}

	// Nothing left and no SAN required: the certificate would name nothing.
	if _, err := cnOnly.Subject(pkix.Name{}); err == nil {
		t.Error("an empty subject on a profile requiring no SAN was accepted")
	}
	withSAN := &Profile{Name: "p", SubjectRDNs: []string{"CN"}, SANRequired: true}
	if _, err := withSAN.Subject(pkix.Name{}); err != nil {
		t.Errorf("an empty subject on a profile that requires a SAN was refused: %v", err)
	}
}

func flatten(seq pkix.RDNSequence) []pkix.AttributeTypeAndValue {
	var out []pkix.AttributeTypeAndValue
	for _, rdn := range seq {
		out = append(out, rdn...)
	}
	return out
}

// TestParse_VocabularyIsClosed: a name outside the vocabulary is refused
// at parse time with the list of what would have been accepted. A typo
// must not become a narrower or a wider certificate.
func TestParse_VocabularyIsClosed(t *testing.T) {
	base := Spec{
		ExtendedKeyUsages: []string{"clientAuth"}, KeyUsages: []string{"digitalSignature"},
		Subject: []string{"CN"}, KeyAlgorithms: []string{"ec-p256"}, ValidityHours: 24,
	}
	if set, err := Parse(map[string]Spec{"ok": base}); err != nil || set["ok"].Validity != 24*time.Hour {
		t.Fatalf("Parse(baseline) = %v, %v", set, err)
	}
	cases := []struct {
		name string
		mut  func(*Spec)
		want string
	}{
		{"extended key usage", func(s *Spec) { s.ExtendedKeyUsages = []string{"serverauth"} }, "unknown extended key usage"},
		{"key usage", func(s *Spec) { s.KeyUsages = []string{"keyCertSign"} }, "unknown key usage"},
		{"san type", func(s *Spec) { s.SANTypes = []string{"hostname"} }, "unknown san type"},
		{"key algorithm", func(s *Spec) { s.KeyAlgorithms = []string{"ed25519"} }, "unknown key algorithm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.mut(&s)
			_, err := Parse(map[string]Spec{"p": s})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse = %v, want it to say %q", err, tc.want)
			}
		})
	}
	if _, err := Parse(map[string]Spec{}); err == nil {
		t.Error("an empty profiles section was accepted")
	}
	if _, err := Parse(map[string]Spec{" ": base}); err == nil {
		t.Error("a blank profile name was accepted")
	}
}

// TestParse_RoundTripsTheBuiltins: the built-ins can be written in the
// configuration vocabulary and come back the same, so an operator can
// start from them.
func TestParse_RoundTripsTheBuiltins(t *testing.T) {
	specs := map[string]Spec{
		"tls-server": {ExtendedKeyUsages: []string{"serverAuth"}, KeyUsages: []string{"digitalSignature", "keyEncipherment"},
			SANTypes: []string{"dns", "ip"}, SANRequired: true, Subject: []string{"CN"},
			KeyAlgorithms: []string{"ec-p256", "ec-p384", "ec-p521", "rsa"}, ValidityHours: 90 * 24},
		"ocsp-responder": {ExtendedKeyUsages: []string{"ocspSigning"}, KeyUsages: []string{"digitalSignature"},
			Subject: []string{"CN"}, KeyAlgorithms: []string{"ec-p256", "ec-p384", "ec-p521"}, ValidityHours: 7 * 24, OCSPNoCheck: true},
	}
	set, err := Parse(specs)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := set.Validate(365 * 24 * time.Hour); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	b := Builtin()
	for name := range specs {
		got, want := set[name], b[name]
		if got.KeyUsage != want.KeyUsage || len(got.ExtKeyUsages) != len(want.ExtKeyUsages) || got.SANRequired != want.SANRequired ||
			got.Validity != want.Validity || got.OCSPNoCheck != want.OCSPNoCheck || len(got.KeyAlgorithms) != len(want.KeyAlgorithms) {
			t.Errorf("%s: parsed %+v, built-in %+v", name, got, want)
		}
	}
}
