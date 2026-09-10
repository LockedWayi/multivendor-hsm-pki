package pkcs11

import (
	"context"
	"io"
)

// VendorAdapter is the PKCS#11 surface every backend implements. It is
// written against the standard operation set only. A vendor's quirks are
// handled inside that vendor's adapter and do not appear here.
//
// Every method that works within a session takes the *Session returned by
// OpenSession. Implementations must reject the call once that session's
// idle timeout or max TTL has passed.
type VendorAdapter interface {
	// Workspaces lists the tokens this adapter can see. See Workspace for
	// what a token maps to per vendor.
	Workspaces(ctx context.Context) ([]Workspace, error)

	// OpenSession opens a session against ws, bounded by opts. The zero
	// value of SessionOptions is replaced with DefaultSessionOptions.
	OpenSession(ctx context.Context, ws Workspace, opts SessionOptions) (*Session, error)
	// CloseSession releases the underlying PKCS#11 session. Idempotent.
	CloseSession(ctx context.Context, s *Session) error

	// LoginToken authenticates the token backing ws and keeps it
	// authenticated until LogoutToken or Close. PKCS#11 authenticates a
	// token for the whole application, so sessions opened afterwards need
	// no login of their own. See tokenlogin.go. pin is zeroed in place
	// before this returns.
	LoginToken(ctx context.Context, ws Workspace, pin []byte, role Role) error
	// LogoutToken drops the token's authentication. Idempotent.
	LogoutToken(ctx context.Context) error
	// TokenLoggedIn reports whether the token is authenticated.
	TokenLoggedIn() bool

	// Login authenticates as role through s. It authenticates the whole
	// token, not the session: every other session on the token becomes
	// authenticated too, a second Login returns CKR_USER_ALREADY_LOGGED_IN,
	// and Logout de-authenticates all of them. Prefer LoginToken. This
	// remains for tests that exercise login failures. pin is zeroed in
	// place before this returns.
	Login(ctx context.Context, s *Session, pin []byte, role Role) error
	// Logout drops the token's authentication, for every session on it.
	Logout(ctx context.Context, s *Session) error

	// GenerateKeyPair creates an EC key pair on the token. The private key
	// never leaves the token; only its handle is returned.
	GenerateKeyPair(ctx context.Context, s *Session, req KeyPairRequest) (KeyPairHandle, error)
	// GenerateSecretKey creates an AES key on the token.
	GenerateSecretKey(ctx context.Context, s *Session, req SecretKeyRequest) (ObjectHandle, error)
	// GenerateRandom returns n bytes from the token's RNG.
	GenerateRandom(ctx context.Context, s *Session, n int) ([]byte, error)

	// FindObjects returns handles for objects matching tmpl.
	FindObjects(ctx context.Context, s *Session, tmpl []Attribute) ([]ObjectHandle, error)
	// GetAttributes reads the requested attributes of obj.
	GetAttributes(ctx context.Context, s *Session, obj ObjectHandle, types []AttributeType) ([]Attribute, error)
	// DestroyObject removes obj from the token. It takes a handle, not a
	// label. CKA_LABEL is not unique in PKCS#11, so a label lookup can
	// match several objects. The caller must resolve the handle first and
	// refuse if the lookup is ambiguous.
	DestroyObject(ctx context.Context, s *Session, obj ObjectHandle) error

	// Sign and Verify use an asymmetric key, for example MechECDSA.
	Sign(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data []byte) ([]byte, error)
	Verify(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data, sig []byte) error

	// Encrypt and Decrypt use a symmetric key, for example MechAESCBCPad.
	Encrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, ciphertext []byte) ([]byte, error)

	// Wrap exports keyToWrap encrypted under wrappingKey. The key material
	// never leaves the token in plaintext.
	Wrap(ctx context.Context, s *Session, wrappingKey, keyToWrap ObjectHandle, mech Mechanism) ([]byte, error)
	// Unwrap imports wrapped as a new token object matching tmpl,
	// decrypted under unwrappingKey inside the token.
	Unwrap(ctx context.Context, s *Session, unwrappingKey ObjectHandle, mech Mechanism, wrapped []byte, tmpl []Attribute) (ObjectHandle, error)

	// Close releases the loaded module and any open sessions. After Close,
	// every method returns ErrAdapterClosed.
	io.Closer
}
