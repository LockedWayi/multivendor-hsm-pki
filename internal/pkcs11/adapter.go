package pkcs11

import (
	"context"
	"io"
)

// VendorAdapter is the vendor-agnostic PKCS#11 surface every HSM backend
// (SoftHSM2 and ProtectServer today; nShield and Luna later — Phase 7)
// implements. It is written against the standard PKCS#11 operation set
// only; a vendor's quirks and extensions are resolved inside that vendor's
// adapter and never appear here (docs/phases/phase-1-pkcs11-core.md).
//
// Every method that operates within a session takes the *Session returned
// by OpenSession. Implementations must reject the call once that session's
// idle timeout or max TTL has elapsed (fail closed — CLAUDE.md §3.4).
type VendorAdapter interface {
	// Workspaces lists the isolated key spaces this adapter can see — see
	// the Workspace type for what that maps to per vendor.
	Workspaces(ctx context.Context) ([]Workspace, error)

	// OpenSession opens a session against ws, bounded by opts. The zero
	// value of SessionOptions is replaced with DefaultSessionOptions.
	OpenSession(ctx context.Context, ws Workspace, opts SessionOptions) (*Session, error)
	// CloseSession releases the underlying PKCS#11 session. Idempotent.
	CloseSession(ctx context.Context, s *Session) error

	// LoginToken authenticates the token backing ws and keeps it
	// authenticated until LogoutToken or Close. This is the login a
	// long-running service wants: PKCS#11 authenticates a token for the
	// whole application, so sessions opened afterward are already
	// authenticated and need no login of their own. See tokenlogin.go.
	// pin is consumed: it is zeroed in place before this returns.
	LoginToken(ctx context.Context, ws Workspace, pin []byte, role Role) error
	// LogoutToken drops the token's authentication. Idempotent.
	LogoutToken(ctx context.Context) error
	// TokenLoggedIn reports whether the token is currently authenticated.
	TokenLoggedIn() bool

	// Login authenticates as the given Role via s.
	//
	// Despite taking a session, this authenticates the whole TOKEN, not
	// that session — PKCS#11 has no per-session login. Every other session
	// on the token becomes authenticated too, a second Login returns
	// CKR_USER_ALREADY_LOGGED_IN, and Logout de-authenticates all of them
	// at once. That makes a login/logout pair around each operation unsafe
	// with concurrent callers, no matter how the calls are serialized.
	//
	// Prefer LoginToken. This remains for callers that genuinely want to
	// drive the login themselves — chiefly tests exercising login failure
	// modes. pin is consumed: it is zeroed in place before this returns.
	Login(ctx context.Context, s *Session, pin []byte, role Role) error
	// Logout drops the token's authentication, for every session on it.
	Logout(ctx context.Context, s *Session) error

	// GenerateKeyPair creates an asymmetric (EC) key pair on the HSM. The
	// private key never leaves the HSM; only its handle is returned.
	GenerateKeyPair(ctx context.Context, s *Session, req KeyPairRequest) (KeyPairHandle, error)
	// GenerateSecretKey creates a symmetric (AES) key on the HSM.
	GenerateSecretKey(ctx context.Context, s *Session, req SecretKeyRequest) (ObjectHandle, error)
	// GenerateRandom returns n bytes from the HSM's RNG.
	GenerateRandom(ctx context.Context, s *Session, n int) ([]byte, error)

	// FindObjects returns handles for objects matching tmpl.
	FindObjects(ctx context.Context, s *Session, tmpl []Attribute) ([]ObjectHandle, error)
	// GetAttributes reads the requested attributes off obj.
	GetAttributes(ctx context.Context, s *Session, obj ObjectHandle, types []AttributeType) ([]Attribute, error)
	// DestroyObject removes obj from the token permanently.
	//
	// This is the one operation in this interface that cannot be undone by
	// calling it again, and it takes a handle rather than a label
	// deliberately: resolving "which object did you mean" is the caller's
	// problem, and CKA_LABEL cannot answer it — the standard places no
	// uniqueness constraint on it (CLAUDE.md §3.8). A caller that destroys
	// by label must refuse when the lookup matches more than one object,
	// the way findKeyByLabel already does.
	DestroyObject(ctx context.Context, s *Session, obj ObjectHandle) error

	// Sign and Verify operate with an asymmetric key (e.g. MechECDSA).
	Sign(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data []byte) ([]byte, error)
	Verify(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data, sig []byte) error

	// Encrypt and Decrypt operate with a symmetric key (e.g. MechAESCBCPad).
	Encrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, ciphertext []byte) ([]byte, error)

	// Wrap exports keyToWrap encrypted under wrappingKey; the plaintext key
	// material never leaves the HSM unencrypted.
	Wrap(ctx context.Context, s *Session, wrappingKey, keyToWrap ObjectHandle, mech Mechanism) ([]byte, error)
	// Unwrap imports wrapped as a new HSM object matching tmpl, decrypting
	// it under unwrappingKey inside the HSM.
	Unwrap(ctx context.Context, s *Session, unwrappingKey ObjectHandle, mech Mechanism, wrapped []byte, tmpl []Attribute) (ObjectHandle, error)

	// Close releases adapter-level resources (the loaded PKCS#11 module and
	// any still-open sessions). After Close, every method returns
	// ErrAdapterClosed.
	io.Closer
}
