// Package pkcs11 is the vendor-agnostic PKCS#11 layer. VendorAdapter is
// written against the standard PKCS#11 surface only. A concrete adapter
// (SoftHSM2Adapter, ProtectServerAdapter) handles its vendor's differences
// and presents this one interface.
package pkcs11

import (
	"time"

	p11 "github.com/miekg/pkcs11"
)

// Workspace is a vendor's isolated key space: an nShield softcard, a Luna
// partition, a ProtectServer slot, a PKCS#11 token in a slot.
//
// Label is for addressing: what an operator types and what config.yaml
// carries. Serial is for identity: what code compares to decide whether
// two workspaces are the same token. PKCS#11 places no uniqueness
// constraint on CKA_LABEL, and permits a slot ID to change between
// reboots. CK_TOKEN_INFO.serialNumber is the field meant for identity;
// RFC 7512 carries token= and serial= as separate URI attributes.
//
// Serial is an opaque string. SoftHSM2 emits a hex-like serial and
// ProtectToolkit forms such as "0000:57270". Only equality is used.
type Workspace struct {
	SlotID uint
	Label  string
	// Serial is CK_TOKEN_INFO.serialNumber with trailing padding trimmed.
	Serial  string
	Present bool
}

// Role selects which PKCS#11 login identity a session authenticates as.
type Role uint

const (
	RoleUser Role = Role(p11.CKU_USER)
	RoleSO   Role = Role(p11.CKU_SO)
)

// SessionOptions bounds a session's lifetime with an idle timeout and a
// maximum TTL, so a forgotten session cannot hold a token session slot
// open.
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

// AttributeType is a CKA_* constant, re-exported so callers never import
// miekg/pkcs11.
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

// NumericAttribute builds an Attribute whose value is a CK_ULONG, for
// FindObjects and Unwrap templates. CK_ULONG is 8 bytes little-endian on
// LP64 Linux, the only platform this service runs on. The width is not
// detected at run time.
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

// ObjectHandle is an opaque reference to an object on the token. It is
// never the key material. The Signer comment in internal/ca says how its
// scope across sessions is handled.
type ObjectHandle uint

// ECCurve selects the curve for GenerateKeyPair. The zero value is P256,
// matching the platform default.
type ECCurve int

const (
	P256 ECCurve = iota
	P384
	P521
)

// KeyPairRequest carries the parameters for generating an EC key pair.
// Only EC is supported; the CA is ECDSA.
type KeyPairRequest struct {
	Curve  ECCurve
	Label  string
	ID     []byte // nil = adapter generates 8 random bytes
	Sign   bool
	Verify bool
	// Extractable permits the private key to leave the token wrapped under
	// another key (C_WrapKey). Default false. The ceremony sets it on the
	// root when the operator asks for a backup-capable root. There is no
	// Sensitive field: GenerateKeyPair always sets CKA_SENSITIVE true.
	Extractable bool
}

// KeyPairHandle holds the two object handles produced by GenerateKeyPair.
type KeyPairHandle struct {
	Public  ObjectHandle
	Private ObjectHandle
}

// SecretKeyRequest carries the parameters for generating an AES key. AES
// is the only symmetric type; it exists to exercise Encrypt, Decrypt, Wrap
// and Unwrap.
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
