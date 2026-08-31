package pkcs11

import (
	"context"
	"io"
)

// VendorAdapter is the vendor-agnostic PKCS#11 surface every HSM backend
// (SoftHSM2 today; nShield, Luna, ProtectServer later — Phase 7) implements.
// It is written against the standard PKCS#11 operation set only; a vendor's
// quirks and extensions are resolved inside that vendor's adapter and never
// appear here (docs/phases/phase-1-pkcs11-core.md).
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

	// Login authenticates the session as the given Role. pin is consumed:
	// callers must not reuse it afterward (see SecurePIN).
	Login(ctx context.Context, s *Session, pin []byte, role Role) error
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
