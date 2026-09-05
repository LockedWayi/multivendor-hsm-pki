package pkcs11

// SoftHSM2Adapter implements VendorAdapter against SoftHSM2's PKCS#11
// module. It is the only backend Phase 1 requires actually running in CI
// ; ProtectServer (this file's sibling,
// protectserver.go) runs the same interface against a real vendor, locally.
//
// SoftHSM2Adapter is a thin named type over the shared pkcs11Adapter
// (base.go): as of sub-task 1.8, every operation the conformance suite
// exercises transfers unchanged between SoftHSM2 and ProtectServer, so
// there is no SoftHSM2-specific override to place here. That absence was
// earned, not assumed — see base.go's doc comment for why this extraction
// waited until a second, real vendor had been proven against the same
// code.
type SoftHSM2Adapter struct {
	*pkcs11Adapter
}

// NewSoftHSM2Adapter loads and initializes the PKCS#11 module at modulePath
// (e.g. /usr/lib/softhsm/libsofthsm2.so).
func NewSoftHSM2Adapter(modulePath string) (*SoftHSM2Adapter, error) {
	base, err := newPKCS11Adapter(modulePath)
	if err != nil {
		return nil, err
	}
	return &SoftHSM2Adapter{pkcs11Adapter: base}, nil
}

var _ VendorAdapter = (*SoftHSM2Adapter)(nil)
