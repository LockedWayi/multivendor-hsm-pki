package pkcs11

// ProtectServerAdapter implements VendorAdapter for the Thales
// ProtectServer family through the ProtectToolkit-C PKCS#11 module. It
// wraps pkcs11Adapter with no overrides. Verified against ProtectToolkit-C
// 7.3.3 software emulation (libctsw.so, token model SW:SWEMUL) only; the
// measured behaviour is listed in docs/architecture.md, "ProtectToolkit-C
// software emulation, as measured".
type ProtectServerAdapter struct {
	*pkcs11Adapter
}

// NewProtectServerAdapter loads and initializes the ProtectToolkit PKCS#11
// module at modulePath: libctsw.so for software emulation, libcthsm.so for
// a ProtectServer appliance.
func NewProtectServerAdapter(modulePath string) (*ProtectServerAdapter, error) {
	base, err := newPKCS11Adapter(modulePath)
	if err != nil {
		return nil, err
	}
	return &ProtectServerAdapter{pkcs11Adapter: base}, nil
}

// Capabilities declares what ProtectToolkit-C 7.3.3 software emulation was
// measured to do.
func (a *ProtectServerAdapter) Capabilities() Capabilities {
	return Capabilities{
		ConcurrentSlotEnumeration:  false, // C_GetSlotList deadlocked under concurrent callers
		SecondInitializeInProcess:  false, // CKR_CRYPTOKI_ALREADY_INITIALIZED
		HandlesSpanSessions:        true,
		HandlesSurviveSessionClose: true,
		ZeroDigest:                 ZeroDigestVerifyRefused, // signs it, then CKR_SIGNATURE_INVALID over its own signature
		// Measured 2026-09-24: the template's CKA_EXTRACTABLE=false reached
		// the restored key. An earlier note recorded the opposite on the
		// same emulator version; the suite now asserts today's measurement
		// and fails the day it changes back.
		UnwrapHonoursExtractable: true,
	}
}

var _ VendorAdapter = (*ProtectServerAdapter)(nil)
