// Package entitlement binds an authenticated identity to what it may ask
// the CA for: which profiles, and which names.
//
// Profiles say what a certificate may be. Entitlements say who may ask
// for it. Without the second, any issuer could mint a tls-client
// certificate carrying another issuer's identity and use it, and the two
// identity lists would separate the operations but not the issuers.
//
// The model is a static mapping in configuration, decided for this phase:
// no request queue, no approval, no delegation. An identity absent from
// the mapping issues nothing, and an entry that grants nothing is refused
// at load rather than left as a binding that can never be satisfied.
package entitlement

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
)

// ErrNotEntitled is the one error a policy refusal returns. It carries
// no detail on purpose: the HTTP layer answers 403 with a fixed message,
// and what the identity is or is not entitled to stays in the server's
// log.
var ErrNotEntitled = errors.New("entitlement: the identity is not entitled to this request")

// NameType is the kind of name a pattern constrains.
type NameType string

// The five name types a certificate this CA issues can carry: the
// subject common name and the four subject-alternative-name types.
const (
	NameCN    NameType = "cn"
	NameDNS   NameType = "dns"
	NameIP    NameType = "ip"
	NameURI   NameType = "uri"
	NameEmail NameType = "email"
)

// Pattern is one name an identity may request, written as
// "<type>:<glob>". The glob's only metacharacter is *, matching any run
// of characters including none, so "dns:*.example.test" is every name
// under example.test and "dns:*" is any DNS name. DNS names match
// case-insensitively, as DNS does; the rest match exactly. An ip pattern
// is an address, a CIDR range, or * for any.
type Pattern struct {
	Type NameType
	raw  string
	re   *regexp.Regexp
	cidr *net.IPNet
	ip   net.IP
	any  bool
}

// String returns the pattern as written.
func (p Pattern) String() string { return string(p.Type) + ":" + p.raw }

// ParsePattern parses "<type>:<glob>".
func ParsePattern(s string) (Pattern, error) {
	typ, rest, ok := strings.Cut(s, ":")
	if !ok || rest == "" {
		return Pattern{}, fmt.Errorf("entitlement: pattern %q is not <type>:<glob>", s)
	}
	p := Pattern{Type: NameType(typ), raw: rest}
	switch p.Type {
	case NameCN, NameURI, NameEmail:
		p.re = globRegexp(rest, false)
	case NameDNS:
		p.re = globRegexp(rest, true)
	case NameIP:
		switch {
		case rest == "*":
			p.any = true
		case strings.Contains(rest, "/"):
			_, cidr, err := net.ParseCIDR(rest)
			if err != nil {
				return Pattern{}, fmt.Errorf("entitlement: pattern %q: %w", s, err)
			}
			p.cidr = cidr
		default:
			ip := net.ParseIP(rest)
			if ip == nil {
				return Pattern{}, fmt.Errorf("entitlement: pattern %q: %q is not an IP address, a CIDR range or *", s, rest)
			}
			p.ip = ip
		}
	default:
		return Pattern{}, fmt.Errorf("entitlement: pattern %q: unknown name type %q (want cn, dns, ip, uri or email)", s, typ)
	}
	return p, nil
}

// globRegexp anchors the glob and quotes everything but *.
func globRegexp(glob string, fold bool) *regexp.Regexp {
	parts := strings.Split(glob, "*")
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	expr := "^" + strings.Join(parts, ".*") + "$"
	if fold {
		expr = "(?i)" + expr
	}
	return regexp.MustCompile(expr)
}

// matches reports whether one name of the pattern's own type matches.
func (p Pattern) matches(name string) bool {
	switch p.Type {
	case NameIP:
		if p.any {
			return true
		}
		ip := net.ParseIP(name)
		if ip == nil {
			return false
		}
		if p.cidr != nil {
			return p.cidr.Contains(ip)
		}
		return p.ip.Equal(ip)
	default:
		return p.re.MatchString(name)
	}
}

// Entitlement is what one identity may request.
type Entitlement struct {
	profiles map[string]bool
	names    []Pattern
}

// Spec is an entitlement as written in configuration.
type Spec struct {
	// Profiles the identity may request, by name. The internal-only
	// profile cannot be listed.
	Profiles []string `yaml:"profiles"`
	// Names the identity may request, as patterns. A name in a request
	// of a type with no pattern here is refused.
	Names []string `yaml:"names"`
}

// Compile turns a Spec into an Entitlement for identity, refusing an
// entry that grants nothing, a profile no client may have, or a pattern
// that does not parse.
func (s Spec) Compile(identity string) (Entitlement, error) {
	e := Entitlement{profiles: make(map[string]bool, len(s.Profiles))}
	if len(s.Profiles) == 0 {
		return Entitlement{}, fmt.Errorf("entitlement: %q lists no profile, so it could issue nothing; remove the entry or grant it something", identity)
	}
	if len(s.Names) == 0 {
		return Entitlement{}, fmt.Errorf("entitlement: %q lists no name pattern, so it could name nothing; remove the entry or grant it something", identity)
	}
	for _, name := range s.Profiles {
		if name == "" {
			return Entitlement{}, fmt.Errorf("entitlement: %q lists an empty profile name", identity)
		}
		if profile.InternalOnly(name) {
			return Entitlement{}, fmt.Errorf("entitlement: %q is granted %q, which no client may obtain; it is issued on the internal path only", identity, name)
		}
		if e.profiles[name] {
			return Entitlement{}, fmt.Errorf("entitlement: %q lists profile %q twice", identity, name)
		}
		e.profiles[name] = true
	}
	for _, raw := range s.Names {
		p, err := ParsePattern(raw)
		if err != nil {
			return Entitlement{}, fmt.Errorf("entitlement: %q: %w", identity, err)
		}
		e.names = append(e.names, p)
	}
	return e, nil
}

// Profiles lists the profile names granted, sorted, for validation
// against the profile set and for logs.
func (e Entitlement) Profiles() []string {
	out := make([]string, 0, len(e.profiles))
	for name := range e.profiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// PermitsProfile reports whether the identity may request name. The
// internal-only profile is refused here too, whatever the entry says:
// Compile refuses it at load, and this is the check at the point of use.
func (e Entitlement) PermitsProfile(name string) bool {
	return e.profiles[name] && !profile.InternalOnly(name)
}

// PermitsNames refuses a request carrying any name, of any type, that no
// pattern of that type matches. The subject common name counts as a
// name; an empty one does not. It returns ErrNotEntitled wrapped with
// the name that failed, for the log, never for the response.
func (e Entitlement) PermitsNames(csr *x509.CertificateRequest) error {
	check := func(typ NameType, name string) error {
		for _, p := range e.names {
			if p.Type == typ && p.matches(name) {
				return nil
			}
		}
		return fmt.Errorf("%w: %s name %q matches no pattern", ErrNotEntitled, typ, name)
	}
	if cn := csr.Subject.CommonName; cn != "" {
		if err := check(NameCN, cn); err != nil {
			return err
		}
	}
	for _, n := range csr.DNSNames {
		if err := check(NameDNS, n); err != nil {
			return err
		}
	}
	for _, ip := range csr.IPAddresses {
		if err := check(NameIP, ip.String()); err != nil {
			return err
		}
	}
	for _, u := range csr.URIs {
		if err := check(NameURI, u.String()); err != nil {
			return err
		}
	}
	for _, m := range csr.EmailAddresses {
		if err := check(NameEmail, m); err != nil {
			return err
		}
	}
	return nil
}

// Map is every issuing identity and what it may request. An identity
// absent from it may request nothing.
type Map map[string]Entitlement

// Parse compiles a configured mapping. Every entry must grant something.
func Parse(specs map[string]Spec) (Map, error) {
	m := make(Map, len(specs))
	for identity, spec := range specs {
		if strings.TrimSpace(identity) == "" {
			return nil, errors.New("entitlement: an entry has an empty identity")
		}
		e, err := spec.Compile(identity)
		if err != nil {
			return nil, err
		}
		m[identity] = e
	}
	return m, nil
}

// Identities lists the identities in the map, sorted.
func (m Map) Identities() []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
