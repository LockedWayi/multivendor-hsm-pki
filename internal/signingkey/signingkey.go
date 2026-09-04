// Package signingkey provisions and inspects the platform's supply-chain
// signing keys — the ones that sign container images and release artifacts,
// as opposed to the CA hierarchy's keys, which internal/ca owns.
//
// The separation is not organisational. These keys live on their own token
// (Phase 4.8, docs/threat-model.md §6.1) precisely so that a process holding
// the CA's session cannot reach them, and a package that could provision
// both from one place would be a standing invitation to hand it one session
// and let it do everything.
//
// Nothing here signs. cosign does the signing, through its own PKCS#11
// binding against the same token; what this package owns is how those keys
// come into existence and what is true of them afterwards.
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

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// labelPattern constrains a signing key's label to a versioned form:
// a purpose, then "-v" and a version number, e.g. image-signing-key-v1.
//
// Enforced rather than documented because the versioning is what makes
// rotation a lifecycle step instead of a breaking rename (CLAUDE.md §3.7).
// A key provisioned once under a bare label is a key whose rotation
// requires every consumer — cosign invocations, admission policies, docs —
// to change on the same day, which in practice means it never rotates. The
// cheap moment to prevent that is before the first label exists.
var labelPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*-v[0-9]+$`)

// ErrLabelTaken reports that the token already holds an object under the
// requested label. Provisioning refuses rather than adding a second object:
// two keys a label cannot distinguish is the ambiguity
// pkcs11.FindKeyByLabel exists to refuse, created deliberately.
var ErrLabelTaken = errors.New("signingkey: label already in use on this token")

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
	// this and nothing else — no HSM, no PIN.
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
// returns what the token then reports about it.
//
// Every parameter that can be checked without touching the token is checked
// first, and the label is confirmed free before anything is generated:
// generation is irreversible, so a validation failure discovered afterwards
// costs an operator a manual cleanup on a token and turns a typo into an
// incident (CLAUDE.md §3.9).
//
// The generated key is CKA_SIGN, CKA_SENSITIVE and not CKA_EXTRACTABLE, and
// carries a random CKA_ID distinct from any other key's. The private half
// is never returned, in any form, and there is no parameter that would make
// it extractable — unlike the CA root, whose extractability is a deliberate
// ceremony-time choice because an offline root has a wrap-based backup
// story. A supply-chain key has no such story: it is cheap to rotate, so
// the answer to losing one is to provision the next version, not to hold a
// copy of it somewhere.
//
// Then it reads the attributes back off the token and fails if they are not
// what was asked for. That is not belt-and-braces. PKCS#11 permits a token
// to ignore an attribute it does not care to enforce, and this platform has
// already been bitten twice by the difference between a template and a
// token's behaviour: CKA_SENSITIVE was false on every key ever generated
// here, and ProtectToolkit ignores CKA_EXTRACTABLE=false on unwrap
// (docs/lessons.md §1 and §6). A key that is silently extractable is not a
// weaker version of the key we asked for; it is a different key with a
// different threat model, and the build must stop rather than sign with it.
func Provision(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, p Params) (Key, error) {
	if !labelPattern.MatchString(p.Label) {
		return Key{}, fmt.Errorf("signingkey: label %q is not a versioned label (want e.g. image-signing-key-v1)", p.Label)
	}
	// No defaulting branch: pkcs11.ECCurve's zero value is already P256,
	// which is the platform default.
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

	// A distinct CKA_ID per key, written to both halves. cosign's PKCS#11
	// binding matches a pair across public and private objects by
	// CKA_ID/CKA_LABEL, so the two must agree; internal/pkcs11's
	// GenerateKeyPair already writes both.
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
		// Not extractable, and not a caller's choice. See the doc comment.
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
	return key, nil
}

// Load reads an existing signing key's public half and protection
// attributes off the token. It does not verify them — Verify does that, so
// that a caller inspecting a key it did not create can see what is actually
// there before deciding.
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

// verifyProtection fails closed when the token did not honour what was
// asked for. Separate from Provision so the check reads as its own step,
// which is what it is: the token is being asked, not trusted.
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
// curve — the check behind "no signing key is also a CA key".
//
// Comparing public keys rather than labels is the whole point: labels are
// what an operator types and prove nothing about what is on the token, and
// two labels pointing at one key pair is exactly the reuse CLAUDE.md §3.6
// forbids and exactly what a label comparison cannot see.
func SameKey(a, b *ecdsa.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Curve == b.Curve && a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}
