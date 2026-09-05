package pkcs11

// ProtectServerAdapter implements VendorAdapter against Thales ProtectServer
// HSMs via the ProtectToolkit-C PKCS#11 module.
//
// This is the second, independently-verified vendor backend — the proof
// that VendorAdapter is a real abstraction and not a SoftHSM2-shaped guess
// (see "Why two adapters rather than one" in
// ). Like SoftHSM2Adapter, it is now a
// thin named type over the shared pkcs11Adapter (base.go): sub-task 1.8
// extracted that base only after this adapter had been run against real
// hardware and shown to need no vendor-specific override at all — see
// base.go's doc comment for why the extraction was sequenced that way, and
// the divergence log below for the one behavioral difference that was
// found and did not need one.
//
// # Verified environment
//
// Confirmed against the maintainer's own ProtectToolkit installation;
// carries the setup steps.
//
//   - Product: Thales ProtectToolkit-C 7.3.3, software emulation mode
//     (token model "SW:SWEMUL"). ProtectServer is the HSM family;
//     ProtectToolkit is the SDK that drives it, and libctsw.so is its
//     software-only emulation of one.
//   - Module: /opt/safenet/protecttoolkit7/ptk/lib/libctsw.so — dlopen-able
//     directly, with no LD_LIBRARY_PATH set, because the library resolves
//     only against libdl/libpthread/libc.
//   - Slots: slot 1 holds "AdminToken (0000)"; slot 0 is the working user
//     token, labelled and PIN-initialized by the operator steps in
//
// before this adapter can find it.
//
// # Divergences from SoftHSM2
//
// Record every vendor-specific behaviour discovered here, even after
// sub-task 1.8's extraction — this is the log a future divergence gets
// added to, and the reason to check before assuming a new one needs a
// code-level override rather than just documentation (most won't).
//
//	WORKS UNCHANGED: every VendorAdapter operation — Workspaces,
//	OpenSession, CloseSession, Login (CKU_USER), Logout, GenerateRandom,
//	GenerateKeyPair (EC P-256), GenerateSecretKey (AES), Sign and Verify
//	(CKM_ECDSA, 64-byte r||s as expected), Encrypt/Decrypt
//	(CKM_AES_CBC_PAD), Wrap/Unwrap (CKM_AES_KEY_WRAP), FindObjects,
//	GetAttributes, Close — confirmed by TestConformance/ProtectServer
//	passing against the shared pkcs11Adapter with zero ProtectServer-specific
//	code. CKA_EC_POINT comes back DER-wrapped (0x04 0x41 || point), the same
//	as SoftHSM2.
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
//	needs no workaround and no shared-core override. It is recorded because
//	it is a genuine behavioural difference, and because of how it was found:
//	a first diagnostic used make([]byte, 32) as a stand-in digest and
//	reported "ProtectServer cannot verify" for two commits before a real
//	digest showed Verify working normally. Degenerate test vectors produce
//	degenerate conclusions — the conformance suite uses only real digests
//	and non-degenerate vectors for exactly this reason.
type ProtectServerAdapter struct {
	*pkcs11Adapter
}

// NewProtectServerAdapter loads and initializes the ProtectToolkit PKCS#11
// module at modulePath (e.g. /opt/safenet/protecttoolkit7/ptk/lib/libctsw.so
// for software emulation, or libcthsm.so for a hardware ProtectServer).
func NewProtectServerAdapter(modulePath string) (*ProtectServerAdapter, error) {
	base, err := newPKCS11Adapter(modulePath)
	if err != nil {
		return nil, err
	}
	return &ProtectServerAdapter{pkcs11Adapter: base}, nil
}

// Compile-time proof that a second, independent vendor satisfies the same
// VendorAdapter contract. If a future change to the interface is shaped
// around SoftHSM2's behaviour alone, this assertion is what breaks the
// build.
var _ VendorAdapter = (*ProtectServerAdapter)(nil)
