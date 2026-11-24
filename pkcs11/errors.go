package pkcs11

import "errors"

var (
	// ErrEmptyPIN is returned by Login when the PIN is zero-length.
	ErrEmptyPIN = errors.New("pkcs11: PIN must not be empty")

	// ErrSessionClosed is returned by any operation on a closed session.
	ErrSessionClosed = errors.New("pkcs11: session is closed")

	// ErrSessionExpired is returned when a session's idle timeout or
	// maximum TTL has passed. The session is closed, never extended.
	ErrSessionExpired = errors.New("pkcs11: session idle timeout or max TTL exceeded")

	// ErrAdapterClosed is returned by any operation after Close.
	ErrAdapterClosed = errors.New("pkcs11: adapter is closed")

	// ErrUnsupportedCurve is returned by GenerateKeyPair for an unknown ECCurve.
	ErrUnsupportedCurve = errors.New("pkcs11: unsupported EC curve")

	// ErrUnsupportedKeySize is returned by GenerateSecretKey for a KeyBits
	// value that is not a valid AES key size.
	ErrUnsupportedKeySize = errors.New("pkcs11: unsupported AES key size")

	// ErrTokenAlreadyLoggedIn is returned by LoginToken when this adapter
	// already holds the token authenticated.
	ErrTokenAlreadyLoggedIn = errors.New("pkcs11: token is already logged in")
)
