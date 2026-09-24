package pkcs11

// Capabilities is what an adapter declares about its module, and what the
// conformance suite measures against it. Every field names a behaviour on
// which two conforming PKCS#11 implementations have been observed to
// differ; each declaration is asserted by a subtest on every backend, so
// a declaration the module no longer matches is a failing test, never a
// silent skip. A difference between vendors is absorbed here, as a
// declaration the core and the suite read, and never as a branch on a
// vendor's name.
//
// The zero value is the conservative declaration: nothing extra is
// promised, so a module that declares nothing is treated as the most
// restrictive one measured so far.
type Capabilities struct {
	// ConcurrentSlotEnumeration declares that C_GetSlotList may be called
	// from several goroutines at once. ProtectToolkit-C 7.3.3 deadlocks
	// there despite CKF_OS_LOCKING_OK, so the shared implementation holds
	// the exclusive lock around Workspaces for every module today; a
	// module declaring true is measured under concurrent callers, and the
	// lock is what a module declaring false keeps.
	ConcurrentSlotEnumeration bool

	// SecondInitializeInProcess declares that a second adapter over the
	// same module may be opened while the first is live. SoftHSM2 permits
	// it through a separate dlopen handle; ProtectToolkit-C answers
	// CKR_CRYPTOKI_ALREADY_INITIALIZED. Code that hands a module to a
	// second component in one process (the ceremony's tests, the cleanup
	// tool) has to know which.
	SecondInitializeInProcess bool

	// HandlesSpanSessions declares that a token object's handle, obtained
	// in one session, is valid in another open session on the same token,
	// as the base specification's application-wide scope implies.
	// Measured 2026-09-24: every backend accepts it, SoftHSM2 2.6.1
	// included, which corrects an earlier note that said otherwise. The
	// shared implementation still resolves a handle per session, which is
	// correct on every module either way.
	HandlesSpanSessions bool

	// HandlesSurviveSessionClose declares that the handle stays valid
	// after the session it was obtained in is closed. The specification
	// permits either; a caller that keeps a handle past its session's
	// life depends on this.
	HandlesSurviveSessionClose bool

	// ZeroDigest declares what the module does with an ECDSA signature
	// over an all-zero digest: signs and verifies it, signs it and then
	// refuses its own signature, or refuses to sign it at all. Three
	// modules gave the three answers. No real message hashes to zero, so
	// this changes nothing in production; it is declared because it was
	// measured, and a test that used a zero stand-in once found it.
	ZeroDigest ZeroDigestBehaviour

	// UnwrapHonoursExtractable declares that C_UnwrapKey applies the
	// template's CKA_EXTRACTABLE=false to the restored key. A restore
	// procedure reads the attribute back before trusting the key either
	// way. Not measurable, and not asserted, on a module whose
	// PrivateKeyWrapRefused is set: the wrap that would produce the
	// ciphertext to restore is refused first.
	UnwrapHonoursExtractable bool

	// PrivateKeyWrapRefused, when not empty, declares that this module
	// refuses to wrap a private key and says why. The backup round trip
	// then asserts the refusal (CKR_KEY_NOT_WRAPPABLE) and fails if the
	// wrap succeeds. Luna refuses under partition policy 1, "Allow private
	// key wrapping", which is off by default.
	PrivateKeyWrapRefused string

	// UnwrapNeedsValueLen declares that unwrapping a secret key needs
	// CKA_VALUE_LEN in the template. No template serves every module: Luna
	// refuses the unwrap without it (CKR_ATTRIBUTE_TYPE_INVALID), SoftHSM2
	// refuses the attribute as CKR_ATTRIBUTE_READ_ONLY, ProtectToolkit-C
	// takes either.
	UnwrapNeedsValueLen bool
}

// ZeroDigestBehaviour is a module's answer to an ECDSA signature over an
// all-zero digest.
type ZeroDigestBehaviour string

const (
	// ZeroDigestAccepted: C_Sign signs it and C_Verify accepts the result.
	ZeroDigestAccepted ZeroDigestBehaviour = "accepted"
	// ZeroDigestVerifyRefused: C_Sign signs it and C_Verify rejects the
	// token's own signature with CKR_SIGNATURE_INVALID.
	ZeroDigestVerifyRefused ZeroDigestBehaviour = "verify-refused"
	// ZeroDigestSignRefused: C_Sign refuses the digest with
	// CKR_DATA_INVALID.
	ZeroDigestSignRefused ZeroDigestBehaviour = "sign-refused"
)
