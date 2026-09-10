// Package signingkey provisions and inspects the supply-chain signing
// keys: the ones that sign container images and release artifacts. The CA
// hierarchy's keys belong to internal/ca. These keys live on their own
// token, so a process holding the CA's session cannot reach them.
//
// Nothing here signs. cosign signs through its own PKCS#11 binding against
// the same token. This package owns how the keys come into existence and
// what is true of them afterwards.
package signingkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// labelPattern requires a versioned label: a purpose, then -v and a
// version number, for example image-signing-key-v1. A key under a bare
// label cannot rotate without every consumer changing on the same day.
var labelPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*-v[0-9]+$`)

// ErrLabelTaken reports that the token already holds an object under the
// requested label. Two keys under one label is the ambiguity
// pkcs11.FindKeyByLabel refuses.
var ErrLabelTaken = errors.New("signingkey: label already in use on this token")

// ValidateLabel reports whether label is a versioned signing-key label.
// Provision applies the same check first, so the CLI and the library
// cannot disagree.
func ValidateLabel(label string) error {
	if !labelPattern.MatchString(label) {
		return fmt.Errorf("signingkey: label %q is not a versioned label (want e.g. image-signing-key-v1)", label)
	}
	return nil
}

// Params describes one signing key to provision.
type Params struct {
	// Label is the versioned CKA_LABEL, e.g. "image-signing-key-v1".
	Label string
	// Curve's zero value is P-256, the platform default.
	Curve pk11.ECCurve
}

// Key is a provisioned signing key, as read back from the token rather than
// as requested.
type Key struct {
	Label string
	// Public is the public half, decoded from CKA_EC_POINT. A verifier needs
	// this and nothing else: no HSM, no PIN.
	Public *ecdsa.PublicKey
	// Sensitive and Extractable are what the token reports, not what was
	// asked for. See Provision for why that distinction is load-bearing.
	Sensitive   bool
	Extractable bool
}

// PEM returns the public key in PKIX PEM form, which is what cosign's
// --key flag consumes for verification and what gets published.
func (k Key) PEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(k.Public)
	if err != nil {
		return nil, fmt.Errorf("signingkey: marshalling %s public key: %w", k.Label, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// Provision generates one signing key pair on the token behind s and
// returns what the token reports about it.
//
// Everything checkable without the token is checked first, and the label
// is confirmed free before anything is generated, because generation is
// irreversible. The key is CKA_SIGN, CKA_SENSITIVE and not
// CKA_EXTRACTABLE, with a random CKA_ID. There is no parameter that makes
// it extractable: a supply-chain key is cheap to rotate, so the answer to
// losing one is the next version, not a backup.
//
// The attributes are then read back off the token, and the key is refused
// if they differ from what was asked. PKCS#11 permits a token to ignore an
// attribute. CKA_SENSITIVE was false on every key this platform generated
// before the read-back existed, and ProtectToolkit ignores
// CKA_EXTRACTABLE=false on unwrap.
func Provision(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, p Params) (Key, error) {
	if err := ValidateLabel(p.Label); err != nil {
		return Key{}, err
	}
	// pkcs11.ECCurve's zero value is P256.
	curve := p.Curve
	ellipticCurve := curve.Curve()
	if ellipticCurve == nil {
		return Key{}, fmt.Errorf("signingkey: %w", pk11.ErrUnsupportedCurve)
	}

	// Both halves, because a label is taken if either object holds it.
	for _, class := range []pk11.ObjectClass{pk11.ClassPublicKey, pk11.ClassPrivateKey} {
		free, err := pk11.LabelIsFree(ctx, adapter, s, class, p.Label)
		if err != nil {
			return Key{}, fmt.Errorf("signingkey: checking label %q: %w", p.Label, err)
		}
		if !free {
			return Key{}, fmt.Errorf("%w: %q", ErrLabelTaken, p.Label)
		}
	}

	// One CKA_ID per key, on both halves. cosign's PKCS#11 binding matches
	// a pair by CKA_ID and CKA_LABEL.
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Key{}, fmt.Errorf("signingkey: generating CKA_ID: %w", err)
	}

	if _, err := adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
		Curve:  curve,
		Label:  p.Label,
		ID:     id,
		Sign:   true,
		Verify: true,
		// Not extractable, and not a caller's choice.
		Extractable: false,
	}); err != nil {
		return Key{}, fmt.Errorf("signingkey: generating %q: %w", p.Label, err)
	}

	key, err := Load(ctx, adapter, s, p.Label, curve)
	if err != nil {
		return Key{}, err
	}
	if err := key.verifyProtection(); err != nil {
		return Key{}, err
	}

	// Is this a new key? See findDuplicatePoint. A duplicate is destroyed:
	// this package made it, and leaving it would hand the caller a label
	// that aliases another purpose's key.
	duplicate, err := findDuplicatePoint(ctx, adapter, s, p.Label, key.Public, curve)
	if err != nil {
		return Key{}, err
	}
	if duplicate != "" {
		destroyErr := destroyKeyPair(ctx, adapter, s, p.Label)
		err := fmt.Errorf("%w: the key just generated under %q is the same key pair as %q already on this token",
			ErrDuplicateKey, p.Label, duplicate)
		if destroyErr != nil {
			return Key{}, fmt.Errorf("%w; and removing it failed, so %q must be destroyed by hand before retrying: %v",
				err, p.Label, destroyErr)
		}
		return Key{}, err
	}
	return key, nil
}

// ErrDuplicateKey reports that a freshly generated key pair is the same key
// pair as one already on the token.
var ErrDuplicateKey = errors.New("signingkey: the token generated a key it had already generated")

// FindDuplicateKey reports the label of a key on the token carrying the
// same public point as pub, ignoring ownLabel, or "" when there is none.
// Exported so the check can be tested on both backends; a test cannot make
// a working RNG collide.
func FindDuplicateKey(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, ownLabel string, pub *ecdsa.PublicKey, curve pk11.ECCurve) (string, error) {
	return findDuplicatePoint(ctx, adapter, s, ownLabel, pub, curve)
}

// findDuplicatePoint returns the label of another key on the token with
// the same public point as pub, or "".
//
// Two fresh P-256 pairs do not collide when the RNG works. ProtectToolkit-C
// 7.3.3 software emulation seeds its RNG identically per C_Initialize, so
// the Nth key pair after each initialisation is the same key pair, across
// processes and days. One key per keytool invocation then means
// image-signing-key-v1 and artifact-signing-key-v1 come out as one key
// under two labels. This is the last moment the platform can refuse.
// inventory.Validate asks the same question of the published document.
//
// Keys on other curves are skipped: a point that does not decode on this
// curve cannot equal one that does.
func findDuplicatePoint(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, ownLabel string, pub *ecdsa.PublicKey, curve pk11.ECCurve) (string, error) {
	ellipticCurve := curve.Curve()
	handles, err := adapter.FindObjects(ctx, s, []pk11.Attribute{
		pk11.NumericAttribute(pk11.AttrClass, uint64(pk11.ClassPublicKey)),
	})
	if err != nil {
		return "", fmt.Errorf("signingkey: listing public keys to check %q is new: %w", ownLabel, err)
	}
	for _, h := range handles {
		attrs, err := adapter.GetAttributes(ctx, s, h, []pk11.AttributeType{pk11.AttrLabel, pk11.AttrEcPoint})
		if err != nil {
			// A key this check could not read is a key it cannot clear.
			return "", fmt.Errorf("signingkey: reading a public key while checking %q is new: %w", ownLabel, err)
		}
		var label string
		var point []byte
		for _, a := range attrs {
			switch a.Type {
			case pk11.AttrLabel:
				label = string(a.Value)
			case pk11.AttrEcPoint:
				point = a.Value
			}
		}
		if label == ownLabel || len(point) == 0 {
			continue
		}
		other, err := pk11.DecodeECPoint(ellipticCurve, point)
		if err != nil {
			continue
		}
		if SameKey(pub, other) {
			return label, nil
		}
	}
	return "", nil
}

// destroyKeyPair removes both halves of the pair carrying label. Used only
// to undo a generation this package has just rejected.
func destroyKeyPair(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, label string) error {
	for _, class := range []pk11.ObjectClass{pk11.ClassPublicKey, pk11.ClassPrivateKey} {
		handle, err := pk11.FindKeyByLabel(ctx, adapter, s, class, label)
		if errors.Is(err, pk11.ErrKeyNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if err := adapter.DestroyObject(ctx, s, handle); err != nil {
			return err
		}
	}
	return nil
}

// Load reads an existing signing key's public half and protection
// attributes off the token, without checking them. Verify checks them.
func Load(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, label string, curve pk11.ECCurve) (Key, error) {
	ellipticCurve := curve.Curve()
	if ellipticCurve == nil {
		return Key{}, fmt.Errorf("signingkey: %w", pk11.ErrUnsupportedCurve)
	}

	pubHandle, err := pk11.FindKeyByLabel(ctx, adapter, s, pk11.ClassPublicKey, label)
	if err != nil {
		return Key{}, fmt.Errorf("signingkey: %w", err)
	}
	pubAttrs, err := adapter.GetAttributes(ctx, s, pubHandle, []pk11.AttributeType{pk11.AttrEcPoint})
	if err != nil {
		return Key{}, fmt.Errorf("signingkey: reading CKA_EC_POINT for %q: %w", label, err)
	}
	if len(pubAttrs) == 0 {
		return Key{}, fmt.Errorf("signingkey: CKA_EC_POINT not returned for %q", label)
	}
	pub, err := pk11.DecodeECPoint(ellipticCurve, pubAttrs[0].Value)
	if err != nil {
		return Key{}, fmt.Errorf("signingkey: decoding public key %q: %w", label, err)
	}

	privHandle, err := pk11.FindKeyByLabel(ctx, adapter, s, pk11.ClassPrivateKey, label)
	if err != nil {
		return Key{}, fmt.Errorf("signingkey: %w", err)
	}
	privAttrs, err := adapter.GetAttributes(ctx, s, privHandle,
		[]pk11.AttributeType{pk11.AttrSensitive, pk11.AttrExtractable})
	if err != nil {
		return Key{}, fmt.Errorf("signingkey: reading protection attributes for %q: %w", label, err)
	}
	key := Key{Label: label, Public: pub}
	for _, a := range privAttrs {
		switch a.Type {
		case pk11.AttrSensitive:
			key.Sensitive = attrTrue(a.Value)
		case pk11.AttrExtractable:
			key.Extractable = attrTrue(a.Value)
		}
	}
	return key, nil
}

// verifyProtection refuses a key whose token did not honour the template.
func (k Key) verifyProtection() error {
	if !k.Sensitive {
		return fmt.Errorf("signingkey: %q reports CKA_SENSITIVE=false on this token; "+
			"its private key can be read out, so it is not a signing key this platform will use", k.Label)
	}
	if k.Extractable {
		return fmt.Errorf("signingkey: %q reports CKA_EXTRACTABLE=true on this token despite being generated "+
			"non-extractable; the token did not honour the template and the key can be wrapped off it", k.Label)
	}
	return nil
}

// Verify re-reads a key from the token and confirms its protection
// attributes, for a caller checking a key it did not just create.
func Verify(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, label string, curve pk11.ECCurve) (Key, error) {
	key, err := Load(ctx, adapter, s, label, curve)
	if err != nil {
		return Key{}, err
	}
	return key, key.verifyProtection()
}

// attrTrue reads a CK_BBOOL. PKCS#11 defines false as a zero byte and true
// as any non-zero one, so this does not compare against 1.
func attrTrue(v []byte) bool {
	for _, b := range v {
		if b != 0 {
			return true
		}
	}
	return false
}

// SameKey reports whether two public keys are the same point on the same
// curve. Labels prove nothing about what is on the token.
func SameKey(a, b *ecdsa.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Curve == b.Curve && a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

// caKeyLabelPattern matches the CA hierarchy's key labels, ca-root-key-v1
// and ca-intermediate-key-v2 and so on. It is suffix-anchored, so a
// deployment that prefixes its labels is still recognised.
var caKeyLabelPattern = regexp.MustCompile(`(^|-)ca-(root|intermediate)-key-v[0-9]+$`)

// ErrCAHierarchyKeyPresent reports that the token being provisioned already
// holds one of the CA hierarchy's private keys.
var ErrCAHierarchyKeyPresent = errors.New("signingkey: token already holds a CA hierarchy private key")

// CheckNoCAHierarchyKey refuses a token that holds a private key under a
// CA-hierarchy label. PKCS#11 authenticates a token, not a key, so a
// process with a session on the CA's token can use every key on it. A
// signing key provisioned there would be correct in every attribute and
// would still void the separation.
//
// Two limits. This searches by label, so a CA key under another name is
// not found. And it looks only at the token it is pointed at. It guards
// against the co-location an operator reaches by accident with this
// repository's naming. The proof of separation is that the CA keys are on
// tokens with different serials, which the ceremony measures, and that
// the service's configuration cannot name this token.
//
// Only private keys are examined. A stray public key confers nothing.
func CheckNoCAHierarchyKey(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session) error {
	handles, err := adapter.FindObjects(ctx, s, []pk11.Attribute{
		pk11.NumericAttribute(pk11.AttrClass, uint64(pk11.ClassPrivateKey)),
	})
	if err != nil {
		return fmt.Errorf("signingkey: listing private keys on the target token: %w", err)
	}
	for _, h := range handles {
		attrs, err := adapter.GetAttributes(ctx, s, h, []pk11.AttributeType{pk11.AttrLabel})
		if err != nil {
			// A key whose label cannot be read is a key this check cannot clear.
			return fmt.Errorf("signingkey: reading the label of a private key on the target token: %w", err)
		}
		for _, a := range attrs {
			if a.Type == pk11.AttrLabel && caKeyLabelPattern.Match(a.Value) {
				return fmt.Errorf("%w: %q. Supply-chain signing keys live on their own token "+
					"(docs/threat-model.md §6.1); provision them on a token the CA does not authenticate",
					ErrCAHierarchyKeyPresent, a.Value)
			}
		}
	}
	return nil
}
