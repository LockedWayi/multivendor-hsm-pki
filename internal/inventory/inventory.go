// Package inventory is the published list of which signing keys a verifier
// may trust, and for what.
//
// One PEM per purpose works until the first rotation. Then every consumer
// has to change on the same day, so the rotation never happens. A verifier
// that holds several key versions at once, each with a state, makes
// rotation a routine change.
//
// The list is signed by inventory-signing-key-v1, on an offline token that
// holds none of the keys it vouches for. Its public half is distributed out
// of band. The signature covers the file's exact bytes, so any
// implementation with SHA-256 and an ECDSA verify can check it:
//
//	openssl dgst -sha256 -verify inventory-signing-key.pub \
//	    -signature key-inventory.json.sig key-inventory.json
//
// ValidUntil bounds how long a stale document stays acceptable; without it
// an attacker who can withhold updates keeps a retired key alive. Version
// is monotonic so a rollback is detectable. Consumers enforce both.
package inventory

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Schema names the format version. It is inside the signed bytes so that a
// future format change cannot be presented as this one.
const Schema = "hsm-pki-platform/key-inventory/v1"

// Purpose is what a key is allowed to sign. A verifier checking an image
// signature must reject a signature made by the artifact key.
type Purpose string

// The purposes this platform issues today.
const (
	PurposeImage    Purpose = "image"
	PurposeArtifact Purpose = "artifact"
)

// Status is a key version's place in the rotation lifecycle. The middle
// state is what makes a transition window expressible.
type Status string

const (
	// StatusActive signs new artifacts and verifies old ones.
	StatusActive Status = "active"
	// StatusVerifyOnly signs nothing new; signatures it already made still
	// verify, for a stated transition window.
	StatusVerifyOnly Status = "verify-only"
	// StatusRetired is destroyed on the token. The entry stays in the
	// inventory so that a verifier meeting an old signature learns the key
	// was retired, rather than learning nothing at all.
	StatusRetired Status = "retired"
)

// Entry is one key version.
type Entry struct {
	// Label is the versioned CKA_LABEL: what an operator types and what a
	// PKCS#11 URI carries.
	Label string `json:"label"`
	// Purpose is what this key may sign.
	Purpose Purpose `json:"purpose"`
	// Curve is the EC curve.
	Curve string `json:"curve"`
	// PublicKeyPEM is the identity: PKIX PEM, the bytes a verifier feeds to
	// cosign or openssl. Two labels carrying one public key is key reuse,
	// and only this field can show it.
	PublicKeyPEM string `json:"public_key"`
	// ValidFrom is when this key version was provisioned.
	ValidFrom time.Time `json:"valid_from"`
	// RetiredAt is when it was destroyed on the token, or nil while it
	// still exists.
	RetiredAt *time.Time `json:"retired_at"`
	// Status is the lifecycle state.
	Status Status `json:"status"`
}

// Inventory is the whole published document.
type Inventory struct {
	Schema string `json:"schema"`
	// Version increases by one on every regeneration and never repeats.
	Version int `json:"version"`
	// GeneratedAt is when this version was produced.
	GeneratedAt time.Time `json:"generated_at"`
	// ValidUntil is when a verifier must stop accepting this document.
	ValidUntil time.Time `json:"valid_until"`
	// Keys is ordered by label, so regenerating an unchanged inventory
	// produces identical bytes and a diff shows only real changes.
	Keys []Entry `json:"keys"`
}

// ErrInvalid reports an inventory that must not be published or trusted.
var ErrInvalid = errors.New("inventory: invalid")

// PublicKey decodes an entry's public key through crypto/x509's PKIX path,
// the path cosign and openssl use.
func (e Entry) PublicKey() (*ecdsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(e.PublicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		return nil, fmt.Errorf("%w: %q does not carry exactly one PUBLIC KEY PEM block", ErrInvalid, e.Label)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing %q public key: %v", ErrInvalid, e.Label, err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %q is a %T, and this platform signs with ECDSA", ErrInvalid, e.Label, parsed)
	}
	return pub, nil
}

// Validate fails closed on anything that would make the document unsafe
// to act on. The duplicate-public-key check catches a correct-looking
// document that lists one key pair under two purposes, which comparing
// labels cannot see.
func (inv Inventory) Validate() error {
	if inv.Schema != Schema {
		return fmt.Errorf("%w: schema is %q, want %q", ErrInvalid, inv.Schema, Schema)
	}
	if inv.Version < 1 {
		return fmt.Errorf("%w: version is %d, want a positive, monotonically increasing number", ErrInvalid, inv.Version)
	}
	if inv.GeneratedAt.IsZero() {
		return fmt.Errorf("%w: generated_at is unset", ErrInvalid)
	}
	// An inventory that never expires keeps a retired key alive for
	// whoever can withhold updates.
	if !inv.ValidUntil.After(inv.GeneratedAt) {
		return fmt.Errorf("%w: valid_until (%s) is not after generated_at (%s)",
			ErrInvalid, inv.ValidUntil.Format(time.RFC3339), inv.GeneratedAt.Format(time.RFC3339))
	}
	if len(inv.Keys) == 0 {
		return fmt.Errorf("%w: no keys; an empty inventory authorises nothing", ErrInvalid)
	}

	seenLabel := make(map[string]bool, len(inv.Keys))
	type keyID struct{ x, y string }
	seenKey := make(map[keyID]string, len(inv.Keys))

	for _, e := range inv.Keys {
		if e.Label == "" {
			return fmt.Errorf("%w: an entry has no label", ErrInvalid)
		}
		if seenLabel[e.Label] {
			return fmt.Errorf("%w: label %q appears twice; a label that resolves to two entries resolves to neither", ErrInvalid, e.Label)
		}
		seenLabel[e.Label] = true

		switch e.Purpose {
		case PurposeImage, PurposeArtifact:
		default:
			return fmt.Errorf("%w: %q has purpose %q, which no verifier here knows how to enforce", ErrInvalid, e.Label, e.Purpose)
		}
		switch e.Status {
		case StatusActive, StatusVerifyOnly, StatusRetired:
		default:
			return fmt.Errorf("%w: %q has status %q, want active, verify-only, or retired", ErrInvalid, e.Label, e.Status)
		}
		if e.Curve == "" {
			return fmt.Errorf("%w: %q states no curve", ErrInvalid, e.Label)
		}
		if e.ValidFrom.IsZero() {
			return fmt.Errorf("%w: %q has no valid_from", ErrInvalid, e.Label)
		}
		// The lifecycle and the timestamp have to agree.
		switch {
		case e.Status == StatusRetired && e.RetiredAt == nil:
			return fmt.Errorf("%w: %q is retired but carries no retired_at", ErrInvalid, e.Label)
		case e.Status != StatusRetired && e.RetiredAt != nil:
			return fmt.Errorf("%w: %q is %s but carries a retired_at", ErrInvalid, e.Label, e.Status)
		}
		if e.RetiredAt != nil && e.RetiredAt.Before(e.ValidFrom) {
			return fmt.Errorf("%w: %q was retired before it was valid", ErrInvalid, e.Label)
		}

		pub, err := e.PublicKey()
		if err != nil {
			return err
		}
		id := keyID{pub.X.String(), pub.Y.String()}
		if other, dup := seenKey[id]; dup {
			return fmt.Errorf("%w: %q and %q are the same key pair under two labels; one key must not serve two purposes",
				ErrInvalid, other, e.Label)
		}
		seenKey[id] = e.Label
	}
	return nil
}

// Active returns the entries a signer may use for purpose.
func (inv Inventory) Active(p Purpose) []Entry {
	var out []Entry
	for _, e := range inv.Keys {
		if e.Purpose == p && e.Status == StatusActive {
			out = append(out, e)
		}
	}
	return out
}

// Verifiable returns the entries a verifier may accept a signature from
// for purpose: active and verify-only, never retired. Signatures by a
// retired key stop verifying on the day it retires; the verify-only window
// exists for that. The entry stays in the document so a verifier can say
// "this key was retired on <date>".
func (inv Inventory) Verifiable(p Purpose) []Entry {
	var out []Entry
	for _, e := range inv.Keys {
		if e.Purpose == p && (e.Status == StatusActive || e.Status == StatusVerifyOnly) {
			out = append(out, e)
		}
	}
	return out
}

// Marshal renders the document as the bytes that get signed and published.
// Indented and newline-terminated, because the file is committed and read
// in diffs.
func (inv Inventory) Marshal() ([]byte, error) {
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("inventory: encoding: %w", err)
	}
	return append(out, '\n'), nil
}

// Parse decodes and validates an inventory document. It does not check the
// signature; Verify does. A regenerating caller needs to read the previous
// document without trusting it.
func Parse(data []byte) (Inventory, error) {
	var inv Inventory
	dec := json.NewDecoder(bytes.NewReader(data))
	// A field this build does not understand may change whether a key
	// should be trusted.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		return Inventory{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := inv.Validate(); err != nil {
		return Inventory{}, err
	}
	return inv, nil
}

// Digest is what gets signed: SHA-256 over the document's exact bytes.
func Digest(document []byte) []byte {
	sum := sha256.Sum256(document)
	return sum[:]
}

// Verify checks a detached signature over document against pub. The
// signature is ASN.1 DER ECDSA: what CKM_ECDSA produces once r||s is
// re-encoded, what openssl dgst -verify expects, and what
// crypto/ecdsa.VerifyASN1 reads.
func Verify(document, signature []byte, pub *ecdsa.PublicKey) error {
	if pub == nil {
		return errors.New("inventory: no public key to verify against")
	}
	if !ecdsa.VerifyASN1(pub, Digest(document), signature) {
		return errors.New("inventory: signature does not verify against the inventory signing key")
	}
	return nil
}

// SignWith produces a detached signature over document with an in-process
// key. It exists for tests. Production signing goes through the offline
// token and never holds a private key in a Go process.
func SignWith(document []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, priv, Digest(document))
}

// ErrExpired reports an inventory whose valid_until has passed.
var ErrExpired = errors.New("inventory: expired")

// checkFresh refuses the document when now is past ValidUntil. Every
// consumer reports this in the same words, so a shell verifier and the
// policy generator cannot drift apart on it.
func (inv Inventory) checkFresh(now time.Time) error {
	if now.After(inv.ValidUntil) {
		return fmt.Errorf("%w: the inventory expired at %s (now %s)", ErrExpired,
			inv.ValidUntil.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return nil
}

// VerifiableAt returns the entries a verifier may accept a signature from
// for purpose p at time now. An entry is included when its status is
// active or verify-only and its valid_from is not after now. Retired
// entries are never included. The whole document is refused with
// ErrExpired when now is past valid_until.
func (inv Inventory) VerifiableAt(p Purpose, now time.Time) ([]Entry, error) {
	if err := inv.checkFresh(now); err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range inv.Verifiable(p) {
		if e.ValidFrom.After(now) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// ActiveAt returns the entries a signer may use for purpose p at time now:
// status active, valid_from not after now. The whole document is refused
// with ErrExpired when now is past valid_until.
func (inv Inventory) ActiveAt(p Purpose, now time.Time) ([]Entry, error) {
	if err := inv.checkFresh(now); err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range inv.Active(p) {
		if e.ValidFrom.After(now) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}
