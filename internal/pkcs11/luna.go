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

// Capabilities declares what a Luna Network HSM 7 (firmware 7.8.7) was
// measured to do through client 10.9.4, on partitions in their default
// policy.
func (a *LunaAdapter) Capabilities() Capabilities {
	return Capabilities{
		ConcurrentSlotEnumeration:  false, // not measured under concurrent callers; the shared lock stays
		SecondInitializeInProcess:  false,
		HandlesSpanSessions:        true,
		HandlesSurviveSessionClose: true,
		ZeroDigest:                 ZeroDigestSignRefused, // C_Sign answers CKR_DATA_INVALID
		// Not measurable while PrivateKeyWrapRefused is set: the wrap that
		// would produce the ciphertext to restore is refused first.
		UnwrapHonoursExtractable: false,
		// Partition policy 1, "Allow private key wrapping", defaults to 0
		// even when the capability is present; the partitions this was
		// measured on keep the default.
		PrivateKeyWrapRefused: "Luna partition policy 1 (Allow private key wrapping) is off",
		UnwrapNeedsValueLen:   true,
	}
}

var _ VendorAdapter = (*LunaAdapter)(nil)
