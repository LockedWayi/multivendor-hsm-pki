// Package pkcs11 provides a vendor-agnostic abstraction over PKCS#11 HSMs.
//
// The interface (VendorAdapter) is designed against the standard PKCS#11
// surface only — no vendor extension leaks into it. A concrete adapter
// (SoftHSM2Adapter, ProtectServerAdapter today; nShield/Luna later, see
// and)
// resolves vendor quirks internally and presents this one interface, the
// way a travel power adapter presents one plug to an appliance regardless
// of which wall socket is behind it.
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
//
// # Which field identifies a token
//
// Label is for *addressing* — it is what an operator knows and types, and
// what config.yaml carries. Serial is for *identity* — it is what two
// workspace values must be compared on to decide whether they are the same
// physical token.
//
// The two are not interchangeable, and using Label as identity is a real
// defect rather than a shortcut. PKCS#11 places no uniqueness constraint on
// CKA_LABEL (it is documented as a description), so two distinct tokens may
// legitimately carry the same one. SlotID is worse still: the standard
// explicitly allows it to change between reboots and reinsertions, so it
// identifies a position, not a token. CK_TOKEN_INFO.serialNumber is the
// field the standard intends for this, which is why RFC 7512's PKCS#11 URI
// scheme carries `token=` (label) and `serial=` as separate attributes for
// exactly this reason.
//
// Serial is treated as an opaque string and never parsed. Vendors format it
// very differently — SoftHSM2 emits a hex-like token serial, ProtectToolkit
// emits forms such as "0000:57270" — and nothing here needs its structure,
// only its equality.
type Workspace struct {
	SlotID uint
	Label  string
	// Serial is CK_TOKEN_INFO.serialNumber, trailing padding trimmed. It is
	// the field to compare when deciding whether two Workspace values name
	// the same token; see the type's doc comment for why Label and SlotID
	// are not.
	Serial  string
	Present bool
}

// Role selects which PKCS#11 login identity a session authenticates as.
type Role uint

const (
	RoleUser Role = Role(p11.CKU_USER)
	RoleSO   Role = Role(p11.CKU_SO)
)

// SessionOptions bounds a session's lifetime. Phase 1 requires both an idle
// timeout and a maximum TTL be enforced
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
// this package is the only vendor-facing surface.
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
// LP64 model). This service targets Linux containers only,
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
// matching the platform default.
type ECCurve int

const (
	P256 ECCurve = iota
	P384
	P521
)

// KeyPairRequest carries the parameters for generating an asymmetric key
// pair. Phase 1 supports EC only — the CA (Phase 2) is ECDSA P-256 by
// default and this is the key type it needs; RSA support is deferred until
// a phase actually requires it.
type KeyPairRequest struct {
	Curve  ECCurve
	Label  string
	ID     []byte // nil = adapter generates 8 random bytes
	Sign   bool
	Verify bool
	// Extractable permits the private key to leave the token wrapped under
	// another key (C_WrapKey). Default false, and it should stay false for
	// every key this platform generates today: the wrap-based backup design
	// that would need it is documented in
	// docs/key-ceremony-and-recovery.md and not built.
	//
	// There is deliberately no Sensitive field. CKA_SENSITIVE is always
	// set true by GenerateKeyPair — see the comment there for what happened
	// when it was a caller's choice.
	Extractable bool
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
