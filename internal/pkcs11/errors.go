package pkcs11

import "errors"

var (
	// ErrEmptyPIN is returned by Login when the PIN is zero-length.
	ErrEmptyPIN = errors.New("pkcs11: PIN must not be empty")

	// ErrSessionClosed is returned by any operation on a session that has
	// already been closed (explicitly, or by idle/TTL expiry).
	ErrSessionClosed = errors.New("pkcs11: session is closed")

	// ErrSessionExpired is returned when a session's idle timeout or
	// maximum TTL has been exceeded. Fail closed (CLAUDE.md §3.4): the
	// session is force-closed the moment this is detected, never silently
	// extended.
	ErrSessionExpired = errors.New("pkcs11: session idle timeout or max TTL exceeded")

	// ErrAdapterClosed is returned by any operation attempted after the
	// adapter's Close method has been called.
	ErrAdapterClosed = errors.New("pkcs11: adapter is closed")

	// ErrUnsupportedCurve is returned by GenerateKeyPair for an ECCurve
	// value this adapter does not implement.
	ErrUnsupportedCurve = errors.New("pkcs11: unsupported EC curve")

	// ErrUnsupportedKeySize is returned by GenerateSecretKey for a
	// SecretKeyRequest.KeyBits value that is not a valid AES key size.
	ErrUnsupportedKeySize = errors.New("pkcs11: unsupported AES key size")
)
