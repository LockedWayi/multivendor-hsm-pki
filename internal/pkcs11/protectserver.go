package pkcs11

import (
	"context"
)

// ProtectServerAdapter implements VendorAdapter against Thales ProtectServer
// HSMs via the ProtectToolkit-C PKCS#11 module.
//
// SKELETON ONLY — every method panics. The implementation is tracked as
// sub-task 1.7 in docs/phases/phase-1-pkcs11-core.md and is deliberately not
// written yet; what exists here is the compile-time proof (see the interface
// assertion at the bottom of this file) that the VendorAdapter contract is
// implementable by a second, independent vendor without the interface
// changing. That proof is the point of the two-adapter design.
//
// # Why this adapter exists alongside SoftHSM2Adapter
//
// SoftHSM2 carries CI and reproducibility: it needs no hardware and no
// proprietary SDK, so anyone can run the full suite. But an abstraction that
// has only ever been implemented once is a guess. ProtectServer is a real
// vendor implementation, and one interface surviving both unchanged is the
// evidence the design actually generalizes. Neither adapter replaces the
// other — see "Why two adapters rather than one" in the Phase 1 file.
//
// # Verified environment (as of the Phase 1 restructure)
//
// These were confirmed against the maintainer's own ProtectToolkit
// installation; docs/protectserver-setup.md carries the setup steps.
//
//   - Product: Thales ProtectToolkit-C 7.3.3, software emulation mode
//     (token model "SW:SWEMUL"). ProtectServer is the HSM family;
//     ProtectToolkit is the SDK that drives it, and libctsw.so is its
//     software-only emulation of one.
//   - Module: /opt/safenet/protecttoolkit7/ptk/lib/libctsw.so — dlopen-able
//     directly, with no LD_LIBRARY_PATH set, because the library resolves
//     only against libdl/libpthread/libc. (LD_LIBRARY_PATH is needed for the
//     ct* command-line tools, not for us.) A libcryptoki.so symlink to the
//     same file sits beside it.
//   - Slots: slot 1 holds "AdminToken (0000)"; slot 0 is the working user
//     token and ships UNINITIALIZED — empty label, no TOKEN-INIT flag, and on
//     a fresh install the Admin token's own PINs are unset too. Workspaces()
//     resolves tokens by label, so slot 0 must be initialized and labelled
//     before this adapter can find anything. That initialization is an
//     operator step, not something this adapter should do on the caller's
//     behalf: silently initializing a token destroys any key material on it.
//
// # Divergences from SoftHSM2
//
// Record every vendor-specific behaviour discovered here — mechanism support,
// attribute quirks, slot and label semantics, session limits. This list is
// what sub-task 1.8 reads when deciding which plumbing is genuinely shared and
// which only looked shared. Do not resolve a divergence by widening the
// VendorAdapter interface; resolve it inside this adapter (CLAUDE.md: vendor
// quirks never leak into the interface).
//
// Established by pointing SoftHSM2Adapter at libctsw.so as a one-off
// diagnostic, before any of this adapter was written.
//
//	WORKS UNCHANGED: Workspaces, OpenSession, Login (CKU_USER), Logout,
//	GenerateRandom, GenerateKeyPair (EC P-256), Sign and Verify (CKM_ECDSA,
//	64-byte r||s as expected), FindObjects, GetAttributes. CKA_EC_POINT comes
//	back DER-wrapped (0x04 0x41 || point), the same as SoftHSM2.
//
//	DIVERGES — all-zero ECDSA digest: C_Sign accepts a digest of all zero
//	bytes and returns a signature, but C_Verify then rejects that signature
//	with CKR_SIGNATURE_INVALID (0xC0). SoftHSM2 2.6.1 accepts it. Reproduced
//	at 32 and 20 bytes; a non-zero digest of either length verifies fine on
//	both. Almost certainly a deliberate guard: an all-zero digest converts to
//	the ECDSA scalar e = 0, a degenerate case some implementations refuse on
//	the verify path while permitting on the sign path.
//
//	This divergence is benign for real use — a digest of an actual message is
//	never all-zero, since producing one would be a preimage break — so it
//	needs no workaround. It is recorded because it is a genuine behavioural
//	difference, and because of how it was found: a first diagnostic used
//	make([]byte, 32) as a stand-in digest and reported "ProtectServer cannot
//	verify" for two commits before a real digest showed Verify working
//	normally. Degenerate test vectors produce degenerate conclusions. Use
//	real digests in the conformance suite.
type ProtectServerAdapter struct {
	// Fields are intentionally undeclared until 1.7. Modelling this adapter's
	// state on SoftHSM2Adapter's before its real constraints are known would
	// bake one vendor's assumptions into both — the exact mistake sub-task 1.8
	// is sequenced to avoid.
	_ struct{}
}

// errNotImplemented is the single panic value every stub raises, so a
// premature call fails loudly and identically rather than returning a zero
// value some caller might mistake for success (CLAUDE.md §3.4, fail closed).
const errNotImplemented = "pkcs11: ProtectServerAdapter is not implemented yet " +
	"(sub-task 1.7, docs/phases/phase-1-pkcs11-core.md)"

// NewProtectServerAdapter will load and initialize the ProtectToolkit PKCS#11
// module at modulePath. Not implemented yet.
func NewProtectServerAdapter(modulePath string) (*ProtectServerAdapter, error) {
	panic(errNotImplemented)
}

// Workspaces lists the ProtectServer tokens visible through the module. Not
// implemented yet.
func (a *ProtectServerAdapter) Workspaces(ctx context.Context) ([]Workspace, error) {
	panic(errNotImplemented)
}

// OpenSession opens a session against ws. Not implemented yet.
func (a *ProtectServerAdapter) OpenSession(ctx context.Context, ws Workspace, opts SessionOptions) (*Session, error) {
	panic(errNotImplemented)
}

// CloseSession releases the underlying PKCS#11 session. Not implemented yet.
func (a *ProtectServerAdapter) CloseSession(ctx context.Context, s *Session) error {
	panic(errNotImplemented)
}

// Login authenticates the session as the given Role. Not implemented yet.
func (a *ProtectServerAdapter) Login(ctx context.Context, s *Session, pin []byte, role Role) error {
	panic(errNotImplemented)
}

// Logout drops the session's authentication. Not implemented yet.
func (a *ProtectServerAdapter) Logout(ctx context.Context, s *Session) error {
	panic(errNotImplemented)
}

// GenerateKeyPair creates an asymmetric key pair on the HSM. Not implemented yet.
func (a *ProtectServerAdapter) GenerateKeyPair(ctx context.Context, s *Session, req KeyPairRequest) (KeyPairHandle, error) {
	panic(errNotImplemented)
}

// GenerateSecretKey creates a symmetric key on the HSM. Not implemented yet.
func (a *ProtectServerAdapter) GenerateSecretKey(ctx context.Context, s *Session, req SecretKeyRequest) (ObjectHandle, error) {
	panic(errNotImplemented)
}

// GenerateRandom returns n bytes from the HSM's RNG. Not implemented yet.
func (a *ProtectServerAdapter) GenerateRandom(ctx context.Context, s *Session, n int) ([]byte, error) {
	panic(errNotImplemented)
}

// FindObjects returns handles for objects matching tmpl. Not implemented yet.
func (a *ProtectServerAdapter) FindObjects(ctx context.Context, s *Session, tmpl []Attribute) ([]ObjectHandle, error) {
	panic(errNotImplemented)
}

// GetAttributes reads the requested attributes off obj. Not implemented yet.
func (a *ProtectServerAdapter) GetAttributes(ctx context.Context, s *Session, obj ObjectHandle, types []AttributeType) ([]Attribute, error) {
	panic(errNotImplemented)
}

// Sign produces a signature over data with an asymmetric key. Not implemented yet.
func (a *ProtectServerAdapter) Sign(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data []byte) ([]byte, error) {
	panic(errNotImplemented)
}

// Verify checks sig over data with an asymmetric key. Not implemented yet.
func (a *ProtectServerAdapter) Verify(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data, sig []byte) error {
	panic(errNotImplemented)
}

// Encrypt encrypts plaintext with a symmetric key. Not implemented yet.
func (a *ProtectServerAdapter) Encrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, plaintext []byte) ([]byte, error) {
	panic(errNotImplemented)
}

// Decrypt decrypts ciphertext with a symmetric key. Not implemented yet.
func (a *ProtectServerAdapter) Decrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, ciphertext []byte) ([]byte, error) {
	panic(errNotImplemented)
}

// Wrap exports keyToWrap encrypted under wrappingKey. Not implemented yet.
func (a *ProtectServerAdapter) Wrap(ctx context.Context, s *Session, wrappingKey, keyToWrap ObjectHandle, mech Mechanism) ([]byte, error) {
	panic(errNotImplemented)
}

// Unwrap imports wrapped as a new HSM object matching tmpl. Not implemented yet.
func (a *ProtectServerAdapter) Unwrap(ctx context.Context, s *Session, unwrappingKey ObjectHandle, mech Mechanism, wrapped []byte, tmpl []Attribute) (ObjectHandle, error) {
	panic(errNotImplemented)
}

// Close releases adapter-level resources. Not implemented yet.
func (a *ProtectServerAdapter) Close() error {
	panic(errNotImplemented)
}

// Compile-time proof that a second, independent vendor satisfies the same
// VendorAdapter contract. If a future change to the interface is shaped around
// SoftHSM2's behaviour alone, this assertion is what breaks the build.
var _ VendorAdapter = (*ProtectServerAdapter)(nil)
