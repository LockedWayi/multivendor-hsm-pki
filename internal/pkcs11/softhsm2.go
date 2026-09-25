package pkcs11

// SoftHSM2Adapter implements VendorAdapter for the SoftHSM2 PKCS#11
// module. It wraps pkcs11Adapter (base.go) with no overrides. SoftHSM2
// passed the full conformance suite with the shared implementation.
type SoftHSM2Adapter struct {
	*pkcs11Adapter
}

// NewSoftHSM2Adapter loads and initializes the PKCS#11 module at
// modulePath, for example /usr/lib/softhsm/libsofthsm2.so.
func NewSoftHSM2Adapter(modulePath string) (*SoftHSM2Adapter, error) {
	base, err := newPKCS11Adapter(modulePath)
	if err != nil {
		return nil, err
	}
	return &SoftHSM2Adapter{pkcs11Adapter: base}, nil
}

// Capabilities declares what SoftHSM2 2.6.1 was measured to do.
func (a *SoftHSM2Adapter) Capabilities() Capabilities {
	return Capabilities{
		ConcurrentSlotEnumeration:  false, // not measured under concurrent callers; the shared lock stays
		SecondInitializeInProcess:  false, // CKR_CRYPTOKI_ALREADY_INITIALIZED, measured 2026-09-24; one C_Initialize per process here too
		HandlesSpanSessions:        true,
		HandlesSurviveSessionClose: true,
		ZeroDigest:                 ZeroDigestAccepted,
		UnwrapHonoursExtractable:   true,
	}
}

var _ VendorAdapter = (*SoftHSM2Adapter)(nil)
