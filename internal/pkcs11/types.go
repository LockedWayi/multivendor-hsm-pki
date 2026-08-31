// Package pkcs11 provides a vendor-agnostic abstraction over PKCS#11 HSMs.
//
// The interface (VendorAdapter) is designed against the standard PKCS#11
// surface only — no vendor extension leaks into it. A concrete adapter
// (SoftHSM2Adapter today; nShield/Luna/ProtectServer later, see
// docs/phases/phase-1-pkcs11-core.md and docs/phases/phase-7-hsm-unseal.md)
// resolves vendor quirks internally and presents this one interface, the
// way a travel power adapter presents one plug to an appliance regardless
// of which wall socket is behind it (docs/architecture.md).
package pkcs11

import (
	"time"

	p11 "github.com/miekg/pkcs11"
)

// Workspace is a vendor HSM's isolated key space. nShield calls it a
// softcard, Luna a partition, ProtectServer a slot; SoftHSM2 and the
// PKCS#11 standard call it a token in a slot. Modeling it abstractly here,
// rather than as a SoftHSM2-shaped concept, is what lets future vendor
// adapters map their own term onto it without this interface changing.
type Workspace struct {
	SlotID  uint
	Label   string
	Present bool
}

// Role selects which PKCS#11 login identity a session authenticates as.
type Role uint

const (
	RoleUser Role = Role(p11.CKU_USER)
	RoleSO   Role = Role(p11.CKU_SO)
)

// SessionOptions bounds a session's lifetime. Phase 1 requires both an idle
// timeout and a maximum TTL be enforced (docs/phases/phase-1-pkcs11-core.md)
// so a forgotten session cannot hold a login — and an HSM session slot —
// open indefinitely.
type SessionOptions struct {
	IdleTimeout time.Duration
	MaxTTL      time.Duration
}

// DefaultSessionOptions returns conservative production defaults: sessions
// idle out after 15 minutes and are force-closed after 8 hours regardless
// of activity.
func DefaultSessionOptions() SessionOptions {
	return SessionOptions{
		IdleTimeout: 15 * time.Minute,
		MaxTTL:      8 * time.Hour,
	}
}

// AttributeType identifies a PKCS#11 object attribute (a CKA_* constant).
// Re-exported here so callers never need to import miekg/pkcs11 directly —
// this package is the only vendor-facing surface (CLAUDE.md §6).
type AttributeType uint

const (
	AttrClass          AttributeType = AttributeType(p11.CKA_CLASS)
	AttrLabel          AttributeType = AttributeType(p11.CKA_LABEL)
	AttrID             AttributeType = AttributeType(p11.CKA_ID)
	AttrToken          AttributeType = AttributeType(p11.CKA_TOKEN)
	AttrPrivate        AttributeType = AttributeType(p11.CKA_PRIVATE)
	AttrSensitive      AttributeType = AttributeType(p11.CKA_SENSITIVE)
	AttrExtractable    AttributeType = AttributeType(p11.CKA_EXTRACTABLE)
	AttrSign           AttributeType = AttributeType(p11.CKA_SIGN)
	AttrVerify         AttributeType = AttributeType(p11.CKA_VERIFY)
	AttrEncrypt        AttributeType = AttributeType(p11.CKA_ENCRYPT)
	AttrDecrypt        AttributeType = AttributeType(p11.CKA_DECRYPT)
	AttrWrap           AttributeType = AttributeType(p11.CKA_WRAP)
	AttrUnwrap         AttributeType = AttributeType(p11.CKA_UNWRAP)
	AttrKeyType        AttributeType = AttributeType(p11.CKA_KEY_TYPE)
	AttrEcParams       AttributeType = AttributeType(p11.CKA_EC_PARAMS)
	AttrEcPoint        AttributeType = AttributeType(p11.CKA_EC_POINT)
	AttrModulus        AttributeType = AttributeType(p11.CKA_MODULUS)
	AttrPublicExponent AttributeType = AttributeType(p11.CKA_PUBLIC_EXPONENT)
)

// Attribute is one PKCS#11 object attribute (type + raw value).
type Attribute struct {
	Type  AttributeType
	Value []byte
}

// ObjectClass identifies a PKCS#11 object class (a CKO_* constant), for use
// with NumericAttribute(AttrClass, ...).
type ObjectClass uint64

const (
	ClassPublicKey  ObjectClass = ObjectClass(p11.CKO_PUBLIC_KEY)
	ClassPrivateKey ObjectClass = ObjectClass(p11.CKO_PRIVATE_KEY)
	ClassSecretKey  ObjectClass = ObjectClass(p11.CKO_SECRET_KEY)
)

// KeyType identifies a PKCS#11 key type (a CKK_* constant), for use with
// NumericAttribute(AttrKeyType, ...).
type KeyType uint64

const (
	KeyTypeEC  KeyType = KeyType(p11.CKK_EC)
	KeyTypeAES KeyType = KeyType(p11.CKK_AES)
)

// NumericAttribute builds an Attribute whose value is a numeric PKCS#11
// field (CKA_CLASS, CKA_KEY_TYPE, and similar) — most commonly used to
// build a FindObjects or Unwrap template.
//
// PKCS#11 encodes these as a native CK_ULONG, whose width is platform-
// dependent (4 bytes on Windows' LLP64 model, 8 bytes on Linux/macOS's
// LP64 model). This service targets Linux containers only (CLAUDE.md §6),
// so this hard-codes the 8-byte little-endian LP64 encoding rather than
// taking on a runtime width check for a platform this project never runs
// on. A caller building attributes by hand with the wrong width is exactly
// the trap this helper exists to remove — see the Phase 1 test suite,
// which hit it first.
func NumericAttribute(t AttributeType, v uint64) Attribute {
	buf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		buf[i] = byte(v >> (8 * i))
	}
	return Attribute{Type: t, Value: buf}
}

// MechanismType identifies a PKCS#11 mechanism (a CKM_* constant).
type MechanismType uint

const (
	MechECDSA        MechanismType = MechanismType(p11.CKM_ECDSA)
	MechECKeyPairGen MechanismType = MechanismType(p11.CKM_EC_KEY_PAIR_GEN)
	MechAESKeyGen    MechanismType = MechanismType(p11.CKM_AES_KEY_GEN)
	MechAESCBCPad    MechanismType = MechanismType(p11.CKM_AES_CBC_PAD)
	MechAESKeyWrap   MechanismType = MechanismType(p11.CKM_AES_KEY_WRAP)
)

// Mechanism selects a PKCS#11 algorithm and carries its parameters (e.g. an
// IV for CBC-mode encryption).
type Mechanism struct {
	Type  MechanismType
	Param []byte
}

// ObjectHandle is an opaque reference to an object living on the HSM (a key,
// a certificate, ...). It is never the key material itself — for a private
// key it is meaningless outside the session it was found or created in.
type ObjectHandle uint

// ECCurve selects the curve for GenerateKeyPair. The zero value is P256,
// matching the platform default (CLAUDE.md §3.3, docs/architecture.md).
type ECCurve int

const (
	P256 ECCurve = iota
	P384
	P521
)

// KeyPairRequest carries the parameters for generating an asymmetric key
// pair. Phase 1 supports EC only — the CA (Phase 2) is ECDSA P-256 by
// default and this is the key type it needs; RSA support is deferred until
// a phase actually requires it (CLAUDE.md: no speculative abstraction).
type KeyPairRequest struct {
	Curve       ECCurve
	Label       string
	ID          []byte // nil = adapter generates 8 random bytes
	Sign        bool
	Verify      bool
	Extractable bool
	Sensitive   bool
}

// KeyPairHandle holds the two object handles produced by GenerateKeyPair.
type KeyPairHandle struct {
	Public  ObjectHandle
	Private ObjectHandle
}

// SecretKeyRequest carries the parameters for generating a symmetric key.
// Phase 1 supports AES only, to exercise Encrypt/Decrypt/Wrap/Unwrap in the
// VendorAdapter interface — EC keys cannot exercise those operations.
type SecretKeyRequest struct {
	KeyBits     int // 128, 192, or 256; 0 defaults to 256
	Label       string
	ID          []byte
	Encrypt     bool
	Decrypt     bool
	Wrap        bool
	Unwrap      bool
	Extractable bool
	Sensitive   bool
}
