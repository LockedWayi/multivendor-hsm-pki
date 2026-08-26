package ca

import "errors"

var (
	// ErrKeyNotFound is returned when no HSM object matches the class and
	// label a lookup was searching for. Bootstrap uses this specifically to
	// distinguish "key does not exist yet" from any other failure.
	ErrKeyNotFound = errors.New("ca: no key object found")

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
)
