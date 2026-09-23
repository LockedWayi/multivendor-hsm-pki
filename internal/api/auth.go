package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/entitlement"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

// Authorization names the clients that may write, and for issuers what
// they may write. A client is identified by its certificate, and the
// certificate must have been issued by this CA: it has to chain to the
// ceremony root at the TLS layer, and its serial has to be in the store
// as issued and not revoked. Chaining alone is not enough, because this
// CA copies the subject and the names an issuer asks for, so any leaf it
// issued could otherwise carry an issuer's name.
//
// An identity is one of the strings ClientIdentities derives from the
// certificate. Matching is exact, so a name that differs by a trailing
// dot or a case is a different client.
type Authorization struct {
	// Issuers may POST /certificates, each for the profiles and the
	// names its entitlement grants and nothing else. An identity absent
	// here issues nothing.
	Issuers entitlement.Map
	// Revokers may POST /certificates/{serial}/revoke, for any serial.
	// Revocation is not bound to who issued the certificate: the store
	// does not record that, and during an incident the ability to
	// withdraw any certificate is the one that matters.
	Revokers []string
}

// issuerIdentities lists who may reach the issuance endpoint at all;
// what each may issue is decided by the entitlement in the handler.
func (a Authorization) issuerIdentities() []string { return a.Issuers.Identities() }

// ClientIdentities returns every name a client certificate can be
// authorised by: each URI SAN as written, then the subject common name
// when there is one. URIs come first because they are what an operator
// is expected to configure (urn:hsm-pki:operator:alice); a common name is
// accepted so a certificate made for a person still works.
func ClientIdentities(cert *x509.Certificate) []string {
	var out []string
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	if cn := cert.Subject.CommonName; cn != "" {
		out = append(out, cn)
	}
	return out
}

// TLSConfig is the configuration for the authenticated listener. The
// service presents identity, a leaf this CA issued over an HSM-held key,
// and every client must present a certificate that chains to trustAnchor,
// the ceremony root. The chain check happens here; whether the leaf is
// one this CA issued, still valid in the store, and named in the
// Authorization lists is decided per request by requireClient.
//
// TLS 1.3 only. Nothing that speaks to this endpoint is a browser from
// another decade, and 1.3 removes the renegotiation and cipher-suite
// surface a client-authenticated server would otherwise carry.
func TLSConfig(identity tls.Certificate, trustAnchor *x509.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(trustAnchor)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{identity},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
}

// clientCtxKey carries the authorised identity into the handler.
const clientCtxKey ctxKey = iota + 1

// clientFromContext returns the identity requireClient authorised, or ""
// outside a protected handler.
func clientFromContext(ctx context.Context) string {
	id, _ := ctx.Value(clientCtxKey).(string)
	return id
}

// requireClient wraps a write handler. It refuses unless the request
// arrived over TLS with a verified client certificate, the certificate is
// one this CA issued and has not revoked, and one of its identities is in
// allowed. Every refusal is a JSON error with a status that says which
// check failed and nothing about the store or the other clients.
func (s *server) requireClient(allowed []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity, err := s.authenticate(r.Context(), r, allowed)
		if err != nil {
			var refusal *authError
			if errors.As(err, &refusal) {
				s.writeError(w, refusal.status, refusal.msg)
				return
			}
			loggerFromContext(r.Context()).Error("client authentication failed", "error", err)
			s.writeError(w, http.StatusInternalServerError, "client authentication failed")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), clientCtxKey, identity)))
	}
}

// authError is a refusal with the status it maps to. Anything else out of
// authenticate is a store failure.
type authError struct {
	status int
	msg    string
}

func (e *authError) Error() string { return e.msg }

func refuse(status int, msg string) error { return &authError{status: status, msg: msg} }

// authenticate returns the identity a request is authorised as, or why it
// is not. The order matters: the transport is checked before the store is
// touched, so a plain-HTTP request never causes a lookup.
func (s *server) authenticate(ctx context.Context, r *http.Request, allowed []string) (string, error) {
	// A handler reached over plain HTTP has no r.TLS. The public surface
	// does not route the write endpoints at all, so this is a second
	// guard, not the first.
	if r.TLS == nil {
		return "", refuse(http.StatusUnauthorized, "this endpoint is served over mutual TLS only")
	}
	// RequireAndVerifyClientCert makes an empty chain impossible, and the
	// listener may have been built without it.
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", refuse(http.StatusUnauthorized, "a client certificate is required")
	}
	leaf := r.TLS.VerifiedChains[0][0]

	// Issued by this CA, and still valid in its records. The chain proves
	// the root vouched for the issuer; only the store says this CA made
	// this certificate and has not withdrawn it.
	rec, found, err := s.store.Get(ctx, leaf.SerialNumber)
	if err != nil {
		return "", fmt.Errorf("looking up the client certificate %s: %w", leaf.SerialNumber, err)
	}
	if !found {
		return "", refuse(http.StatusForbidden, "the client certificate was not issued by this CA")
	}
	// The serial addressed a record. This confirms it is the record for
	// this certificate and not one under another issuer beneath the same
	// root that happens to carry the number.
	if rec.Subject.String() != leaf.Subject.String() {
		return "", refuse(http.StatusForbidden, "the client certificate does not match this CA's record of it")
	}
	if rec.Status == store.StatusRevoked {
		return "", refuse(http.StatusForbidden, "the client certificate has been revoked")
	}

	for _, id := range ClientIdentities(leaf) {
		for _, a := range allowed {
			if id == a {
				return id, nil
			}
		}
	}
	return "", refuse(http.StatusForbidden, "the client is not authorised for this operation")
}
