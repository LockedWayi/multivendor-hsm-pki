package pkcs11

// LunaAdapter implements VendorAdapter for Thales Luna Network HSM 7
// partitions through the Luna HSM Client's libCryptoki2.so. It wraps
// pkcs11Adapter with no overrides. Measured against Luna HSM Client 10.9.4
// (minimal client) and Luna HSM Firmware 7.8.7, password authentication.
//
// The module reads its configuration file from ChrystokiConfigurationPath,
// which must be set in the process environment before the module is
// loaded; the partitions it exposes are the ones assigned to this client
// on the appliance.
type LunaAdapter struct {
	*pkcs11Adapter
}

// Luna partition roles beyond the two standard ones. The Crypto Officer
// is the standard CKU_USER (RoleUser) and the Partition Security Officer
// is CKU_SO (RoleSO). The values are Luna's vendor-defined user types, as
// the Luna client's own Java binding declares them
// (com.safenetinc.jcprov.constants.CKU): 0x80000002 is not a partition
// role and C_Login rejects it with CKR_INVALID_ENTRY_TYPE.
const (
	// LunaRoleCryptoUser is the Crypto User (CU), a read-mostly role.
	LunaRoleCryptoUser Role = 0x80000001
	// LunaRoleLimitedCryptoOfficer is the Limited Crypto Officer (LCO),
	// available on V1 partitions.
	LunaRoleLimitedCryptoOfficer Role = 0x80000003
)

// NewLunaAdapter loads and initializes the Luna PKCS#11 module at
// modulePath, for example <client>/libs/64/libCryptoki2.so.
func NewLunaAdapter(modulePath string) (*LunaAdapter, error) {
	base, err := newPKCS11Adapter(modulePath)
	if err != nil {
		return nil, err
	}
	return &LunaAdapter{pkcs11Adapter: base}, nil
}

var _ VendorAdapter = (*LunaAdapter)(nil)
