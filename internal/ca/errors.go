package ca

import "errors"

var (
	// ErrKeyNotFound is returned when no HSM object matches the class and
	// label a lookup was searching for. The ceremony uses it specifically to
	// distinguish "key does not exist yet" from any other failure.
	ErrKeyNotFound = errors.New("ca: no key object found")

	// ErrRootCertificateRejected is returned by LoadIntermediate when the
	// certificate it was pointed at is self-signed — a root. The online
	// service holds the intermediate only; a configuration that would put a
	// root online is refused rather than warned about
	//
	ErrRootCertificateRejected = errors.New("ca: refusing to run an online service on a root certificate")

	// ErrNotAnIntermediate is returned by LoadIntermediate when the
	// certificate is not usable as this platform's intermediate tier: not a
	// CA at all, not constrained to pathlen:0, or missing the key usages an
	// issuing CA needs (keyCertSign for certificates, cRLSign for the CRL
	// this service also publishes).
	ErrNotAnIntermediate = errors.New("ca: certificate is not a valid intermediate for this platform")

	// ErrIssuerNotValid is returned when the issuing certificate is outside
	// its own validity window — expired, or not yet valid. Nothing it signs
	// can chain, because RFC 5280 path validation checks every certificate
	// in the path against the same instant, so signing under it produces
	// certificates that are invalid from the moment they are issued.
	ErrIssuerNotValid = errors.New("ca: issuing certificate is outside its own validity window")

	// ErrValidityExceedsIssuer is returned by Issue when the requested leaf
	// lifetime would end after the issuer's own NotAfter. Such a
	// certificate advertises a validity the chain cannot honor: it becomes
	// unusable when its issuer expires, whatever its own NotAfter claims.
	ErrValidityExceedsIssuer = errors.New("ca: certificate validity would outlive its issuer")

	// ErrKeyCertMismatch is returned by LoadIntermediate when the HSM key
	// found under the configured label is not the key the loaded certificate
	// certifies. Signing with it would produce certificates that chain to
	// nothing.
	ErrKeyCertMismatch = errors.New("ca: HSM key does not match the loaded certificate")

	// ErrInvalidCSRSignature is returned by Issue when the CSR's
	// self-signature does not verify — the strongest evidence a CSR was
	// tampered with or was never actually signed by the key it names.
	ErrInvalidCSRSignature = errors.New("ca: CSR signature is invalid")

	// ErrEmptySubject is returned by Issue when a CSR carries no usable
	// subject identity at all.
	ErrEmptySubject = errors.New("ca: CSR subject is empty")

	// ErrDisallowedKeyType is returned by Issue when a CSR's public key is
	// not on the allow-list (ECDSA P-256/P-384/P-521, or RSA >= 2048 bits).
	ErrDisallowedKeyType = errors.New("ca: CSR public key type is not allowed")

	// ErrNoDistributionPoints is returned by Issue when the CA has no usable
	// CRL distribution point or AIA CA-Issuers URL to write into the
	// certificate. It describes this CA's own configuration, not the
	// caller's request, so the HTTP layer maps it to a 500 rather than a
	// 4xx (internal/api.issueErrorResponse).
	ErrNoDistributionPoints = errors.New("ca: no leaf distribution points configured")
)
