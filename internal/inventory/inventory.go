// Package inventory is the published statement of which signing keys a
// verifier is allowed to trust, and for what (the key lifecycle,
// "The key inventory: what a verifier is allowed to
// trust").
//
// # Why a list, and not one key per purpose
//
// Publishing a single PEM per purpose answers "is this signature valid"
// until the first rotation, at which point every consumer — a cosign
// invocation, an admission policy, a README's verification recipe — has to
// change on the same day. In practice that means the rotation never
// happens, which is how a key outlives the reason anyone trusted it. A
// verifier that can hold several key versions at once, each with a state,
// is what makes rotation a routine change instead of a flag day.
//
// # Why it is signed, and by what
//
// An unsigned list of trusted keys is an invitation: whoever can edit it
// can add their own key and thereby authorise their own signatures. So the
// inventory is signed, and the key that signs it must satisfy one property
// — it is not one of the keys it vouches for, and it is not reachable from
// any process that holds them. That is the invariant behind TUF's offline
// root role, Sigstore's own trust root, and a classic offline X.509 root:
// the anchor is offline and separate. This repository's answer is
// `inventory-signing-key-v1` on an offline token of its own (Phase 4.8),
// whose public half is distributed out of band, the same way TUF bootstraps
// `root.json`.
//
// Its own token rather than the CA root's, for two reasons that pull the
// same way. The root's token is opened for a ceremony and nothing else, so
// putting the inventory key there would make every supply-chain rotation a
// root-token access — which in a real organisation means witnesses and a
// procedure, and a control that expensive is a control that gets skipped.
// And keeping them apart means `signingkey.CheckNoCAHierarchyKey` stays
// absolute: no signing key of any purpose shares a token with a CA key,
// with no exception carved out for this one.
//
// The signature covers the inventory file's exact bytes, so verifying it
// needs no knowledge of this package:
//
//	openssl dgst -sha256 -verify inventory-signing-key.pub \
//	    -signature key-inventory.json.sig key-inventory.json
//
// That is deliberate. A signature over a canonical form
// this package computes could only be checked by code that agrees with this
// package about canonicalization, which is the closed loop independent verification exists to
// forbid. Signing the bytes on disk means any implementation with a SHA-256
// and an ECDSA verify can check it.
//
// # Freshness and rollback
//
// Two fields exist for attacks a plain list does not address. ValidUntil
// bounds how long a stale inventory stays acceptable — without it, an
// attacker who can withhold updates replays yesterday's list forever, which
// keeps a retired key alive (TUF calls this a freeze attack). Version is
// monotonic, so a verifier that has seen version N refuses N-1 and an old
// inventory cannot be rolled back over a newer one. Neither is enforceable
// by this package alone; both are only checkable because they are recorded.
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
// signature must be able to reject a signature made by the artifact key, or
// the purpose separation purpose separation requires is nominal — it would hold
// against a mistake and not against anyone who read the label.
type Purpose string

// The purposes this platform issues today. Phase 8's audit-signing key
// joins them under the same rules.
const (
	PurposeImage    Purpose = "image"
	PurposeArtifact Purpose = "artifact"
)

// Status is a key version's place in the rotation lifecycle.
//
// The middle state is the reason the inventory exists at all. Without it,
// the day a new key version appears is the day everything signed by the
// previous one becomes unverifiable — and for container images still
// running in a cluster, that is a live failure rather than a historical
// one.
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
	// Label is the versioned CKA_LABEL. Addressing, not identity — what an
	// operator types and what a PKCS#11 URI carries.
	Label string `json:"label"`
	// Purpose is what this key may sign.
	Purpose Purpose `json:"purpose"`
	// Curve is the EC curve, stated so that adding another is a data change
	// rather than an assumption a verifier made.
	Curve string `json:"curve"`
	// PublicKeyPEM is the identity: PKIX PEM, exactly the bytes a verifier
	// feeds to cosign or openssl. Two labels carrying one public key is the
	// key reuse purpose separation forbids, and this is the only field that can see it.
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

// PublicKey decodes an entry's public key.
//
// It parses through crypto/x509's generic PKIX path — the same path cosign
// and openssl use — rather than through anything that knows how this
// repository wrote it, so a document this accepts is a document a foreign
// verifier can also read.
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

// Validate fails closed on anything that would make the document unsafe to
// act on, rather than leaving each consumer to notice for itself
//
// The check worth naming is the duplicate-public-key one. Every other rule
// here catches a malformed document; that one catches a *correct-looking*
// document describing key reuse — two purposes resolving to one key pair,
// which is precisely what purpose separation forbids and precisely what comparing labels
// cannot see. It is the same reasoning as signingkey.SameKey, applied to
// the published artifact rather than to the token.
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
	// An inventory that never expires is one an attacker who can withhold
	// updates replays forever, keeping a retired key alive indefinitely.
	if !inv.ValidUntil.After(inv.GeneratedAt) {
		return fmt.Errorf("%w: valid_until (%s) is not after generated_at (%s)",
			ErrInvalid, inv.ValidUntil.Format(time.RFC3339), inv.GeneratedAt.Format(time.RFC3339))
	}
	if len(inv.Keys) == 0 {
		return fmt.Errorf("%w: no keys — an empty inventory authorises nothing and is more likely a generation bug than an intent", ErrInvalid)
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
		// The lifecycle and the timestamp have to agree. A key marked
		// retired with no retirement date, or still active with one, means
		// the generator and the token disagree about what happened — and
		// the entry no longer bounds what a signature's date can be checked
		// against, which is the whole reason the field is there.
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
			return fmt.Errorf("%w: %q and %q are the same key pair under two labels — "+
				"one key serving two purposes is the reuse purpose separation forbids, and only the public key can see it",
				ErrInvalid, other, e.Label)
		}
		seenKey[id] = e.Label
	}
	return nil
}

// Active returns the entries a signer may use for purpose. Everything else
// verifies only, which is the distinction the whole lifecycle exists to
// express.
func (inv Inventory) Active(p Purpose) []Entry {
	var out []Entry
	for _, e := range inv.Keys {
		if e.Purpose == p && e.Status == StatusActive {
			out = append(out, e)
		}
	}
	return out
}

// Verifiable returns the entries a verifier may accept a signature from for
// purpose: the active ones and the verify-only ones, never the retired.
//
// A retired key is excluded deliberately, and it is worth being clear about
// what that costs. Signatures it made stop verifying through the inventory
// on the day it retires, which is why the verify-only window exists and why
// retiring a version is a decision with a date attached rather than a
// cleanup. The entry itself stays in the document so that a verifier
// meeting such a signature can say "this key was retired on <date>" instead
// of "unknown key".
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
//
// Indented and newline-terminated because this file is committed to the
// repository and read in diffs: a single-line JSON blob would make every
// rotation an unreviewable one-line change, and reviewability is most of
// what checking it in buys.
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

// Parse decodes and validates an inventory document.
//
// It does not check the signature — Verify does, and the separation is
// deliberate: a caller regenerating the document needs to read the previous
// one for its version number and valid_from dates, which is a different
// question from whether to trust it.
func Parse(data []byte) (Inventory, error) {
	var inv Inventory
	dec := json.NewDecoder(bytes.NewReader(data))
	// Unknown fields are a refusal, not a shrug. A document carrying a
	// field this build does not understand may be saying something about a
	// key that changes whether it should be trusted, and silently ignoring
	// it is the fail-open answer.
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
//
// Over the file rather than over a canonical re-encoding, so that a
// verifier needs nothing from this package — see the package comment.
func Digest(document []byte) []byte {
	sum := sha256.Sum256(document)
	return sum[:]
}

// Verify checks a detached signature over document against pub.
//
// ASN.1 DER ECDSA, which is what PKCS#11's CKM_ECDSA produces once the
// r||s pair is re-encoded, what openssl dgst -verify expects, and what
// crypto/ecdsa.VerifyASN1 reads. One encoding across all three is the point:
// a signature this platform emits is checkable by software that has never
// seen this repository.
func Verify(document, signature []byte, pub *ecdsa.PublicKey) error {
	if pub == nil {
		return errors.New("inventory: no public key to verify against")
	}
	if !ecdsa.VerifyASN1(pub, Digest(document), signature) {
		return errors.New("inventory: signature does not verify against the inventory signing key")
	}
	return nil
}

// SignWith produces a detached signature over document using an in-process
// key.
//
// This exists for tests and for a verifier's cross-check, never for
// production signing: the platform's inventory is signed on the offline
// token through a crypto.Signer that never holds the private key, and a
// private key that a Go process can hold is one this platform's rules do
// not permit for a signing purpose. It is here rather than
// in a test file so that the signing and verifying halves of the format
// stay defined in one place.
func SignWith(document []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, priv, Digest(document))
}
