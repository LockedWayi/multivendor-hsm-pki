package ca

import "errors"

var (
	// ErrKeyNotFound reports that no token object matched the class and label.
	ErrKeyNotFound = errors.New("ca: no key object found")

	// ErrRootCertificateRejected is returned by LoadIntermediate for a
	// self-signed certificate. A root is never run online.
	ErrRootCertificateRejected = errors.New("ca: refusing to run an online service on a root certificate")

	// ErrNotAnIntermediate is returned by LoadIntermediate for a certificate
	// that is not a CA, is not pathlen:0, or lacks keyCertSign or cRLSign.
	ErrNotAnIntermediate = errors.New("ca: certificate is not a valid intermediate for this platform")

	// ErrIssuerNotValid is returned when the issuer is outside its own validity window.
	ErrIssuerNotValid = errors.New("ca: issuing certificate is outside its own validity window")

	// ErrValidityExceedsIssuer is returned by Issue when the leaf would end
	// after the issuer's NotAfter.
	ErrValidityExceedsIssuer = errors.New("ca: certificate validity would outlive its issuer")

	// ErrKeyCertMismatch is returned by LoadIntermediate when the key under
	// the configured label is not the key the certificate certifies.
	ErrKeyCertMismatch = errors.New("ca: HSM key does not match the loaded certificate")

	// ErrInvalidCSRSignature is returned by Issue when the CSR's
	// self-signature does not verify.
	ErrInvalidCSRSignature = errors.New("ca: CSR signature is invalid")

	// ErrEmptySubject is returned by Issue when a CSR carries no subject.
	ErrEmptySubject = errors.New("ca: CSR subject is empty")

	// ErrDisallowedKeyType is returned by Issue when a CSR's public key is
	// not ECDSA P-256/P-384/P-521 or RSA of at least 2048 bits.
	ErrDisallowedKeyType = errors.New("ca: CSR public key type is not allowed")

	// ErrNoDistributionPoints is returned by Issue when the CA has no CRL
	// distribution point or AIA URL to write. The HTTP layer maps it to a 500.
	ErrNoDistributionPoints = errors.New("ca: no leaf distribution points configured")
)
