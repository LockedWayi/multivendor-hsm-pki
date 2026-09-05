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
// rotation a lifecycle step instead of a breaking rename.
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

// ValidateLabel reports whether label is a versioned signing-key label.
//
// Exported so a caller can refuse a typo before it opens a session, without
// restating the pattern: Provision applies exactly this check as its first
// step, so the CLI and the library cannot disagree about what a valid label
// is. Duplicating the rule in cmd/hsm-pki-keytool would create a second
// place for the key lifecycle's versioning to drift out of.
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
// incident.
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
// . A key that is silently extractable is not a
// weaker version of the key we asked for; it is a different key with a
// different threat model, and the build must stop rather than sign with it.
func Provision(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, p Params) (Key, error) {
	if err := ValidateLabel(p.Label); err != nil {
		return Key{}, err
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

	// And finally: is this actually a new key? See findDuplicatePoint for
	// why that is a real question and not a tautology. A duplicate is
	// destroyed rather than returned — we made it, so removing it is ours
	// to do, and leaving it would hand the caller a label that silently
	// aliases another purpose's key.
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

// FindDuplicateKey reports the label of a key on the token carrying the same
// public point as pub, ignoring the object named by ownLabel, or "" when
// there is none.
//
// Exported so the check can be tested against a real token on both backends
// rather than only through the path that triggers it: forcing Provision to
// generate a colliding key is not something a test can arrange on a backend
// whose RNG works, and a guard nobody can exercise deliberately is a guard
// nobody has seen work.
func FindDuplicateKey(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, ownLabel string, pub *ecdsa.PublicKey, curve pk11.ECCurve) (string, error) {
	return findDuplicatePoint(ctx, adapter, s, ownLabel, pub, curve)
}

// findDuplicatePoint returns the label of another key on the token carrying
// the same public point as pub, or "" when the key really is new.
//
// # Why this is not paranoia
//
// It reads as a tautology — two freshly generated P-256 pairs colliding has
// a probability nobody needs to defend against — right up until a token's
// RNG is not what the caller assumes. Measured on ProtectToolkit-C 7.3.3 in
// software emulation, 2026-09-04: the RNG is seeded deterministically per
// C_Initialize, so the Nth key pair generated after each library
// initialisation is byte-for-byte the same key pair, across processes and
// across days. C_GenerateRandom repeats identically too, so it is the whole
// RNG rather than key generation alone.
//
// That collides head-on with how this platform provisions: one key per
// keytool invocation, which is one C_Initialize each, which on that backend
// means image-signing-key-v1 and artifact-signing-key-v1 come out as *one
// key under two labels* — the precise reuse purpose separation forbids,
// arriving silently, with every other attribute correct.
//
// So the check is empirical rather than theoretical, and it belongs here
// because this is the only moment the platform can still refuse. It is also
// the same question inventory.Validate asks of the published document; two
// layers, because one of them is the layer an operator meets first.
//
// Keys on other curves are skipped rather than treated as errors: a point
// that does not decode on this curve is a key from some other purpose
// entirely, and it cannot be equal to one that does.
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
			// Fail closed: a key this check could not read is a key it
			// cannot clear, and "probably fine" is not an answer to "did
			// the token just hand me somebody else's key".
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
// to undo a generation this package has just decided to reject.
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
// two labels pointing at one key pair is exactly the reuse purpose separation
// forbids and exactly what a label comparison cannot see.
func SameKey(a, b *ecdsa.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Curve == b.Curve && a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

// caKeyLabelPattern matches the labels this repository gives the CA
// hierarchy's key pairs — `ca-root-key-v1`, `ca-intermediate-key-v2`, and
// so on under the versioned scheme of the key lifecycle.
//
// It is deliberately suffix-anchored rather than whole-string-anchored: a
// deployment (or this repository's own test harness) may carry a prefix on
// every label it creates, and a guard that only recognises the bare form
// would stop recognising the thing it exists to find the moment anyone
// namespaced their labels. Matching more than strictly necessary is the
// safe direction for a refusal.
var caKeyLabelPattern = regexp.MustCompile(`(^|-)ca-(root|intermediate)-key-v[0-9]+$`)

// ErrCAHierarchyKeyPresent reports that the token being provisioned already
// holds one of the CA hierarchy's private keys.
var ErrCAHierarchyKeyPresent = errors.New("signingkey: token already holds a CA hierarchy private key")

// CheckNoCAHierarchyKey fails closed when the token behind s carries a
// private key under a CA-hierarchy label, and is the provisioning-time
// enforcement of Phase 4.8's third-token decision.
//
// That decision is the one thing about these keys that a later reader
// cannot recover from the objects themselves: the supply-chain keys live on
// their own token because PKCS#11 authenticates a *token*, not a key, so a
// process holding a session on the CA's online token can find and use every
// key on it (docs/threat-model.md §6.1). Provisioning an image key onto
// that token would leave every object individually correct — right label,
// right attributes, distinct CKA_ID — while silently voiding the separation
// claim the platform makes. The cheap moment to catch that is the one
// moment it is still reversible, before the label is taken.
//
// Two limits, stated rather than glossed. This searches by label, and a
// label is not an identity — a CA key provisioned under
// some other name is not found here. And it only looks at the token it is
// pointed at. So this is a guard against the co-location an operator can
// reach by accident with this repository's own naming, not a proof of
// separation; the proof is that the CA hierarchy's keys are on tokens whose
// serials differ, which the ceremony measures, and that the service's
// configuration has no field able to name this one.
//
// Only private keys are examined. A stray CA public key on this token
// discloses nothing and confers no ability to sign; what makes co-location
// dangerous is a private key reachable from a session, which is what this
// looks for.
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
			// Fail closed: a key whose label cannot be read is a key this
			// check cannot clear, and proceeding would mean provisioning
			// onto a token whose contents are partly unknown.
			return fmt.Errorf("signingkey: reading the label of a private key on the target token: %w", err)
		}
		for _, a := range attrs {
			if a.Type == pk11.AttrLabel && caKeyLabelPattern.Match(a.Value) {
				return fmt.Errorf("%w: %q. Supply-chain signing keys live on their own token "+
					"(Phase 4.8, docs/threat-model.md §6.1) — provision them on a token the CA does not authenticate",
					ErrCAHierarchyKeyPresent, a.Value)
			}
		}
	}
	return nil
}
