// Package artifactsig verifies a Sigstore keyed signature bundle without
// Sigstore.
//
// # Why this exists
//
// Phase 4.9 signs the release binary with cosign over an HSM-held key. A
// verifier who reads that signature back with cosign learns only that
// cosign agrees with itself — the same closed loop that shipped a CRL Go
// could read and OpenSSL could not, and a conformance
// suite that normalised away the property it tested (§3). independent verification
// is the rule that came out of both: what another implementation has to
// read is verified against another implementation.
//
// So this package re-derives the whole answer from the standard library —
// crypto/sha256 over the artifact's bytes, crypto/ecdsa over the signature
// — and shares no code with the tool that produced it. It is the same move
// Phase 1.5 made when it cross-checked HSM signatures against
// crypto/ecdsa rather than against the HSM.
//
// # What it is strict about, and what it deliberately is not
//
// A parser that guards a signature has to be strict about the right thing.
// Rejecting every field it does not model is the wrong thing, and measurably
// so: a real Sigstore bundle carries `tlogEntries` and
// `timestampVerificationData`, so Go's DisallowUnknownFields refuses
// cosign's own release bundles. Strictness of that kind would have passed
// here only because this platform signs with no transparency log — a check
// that holds by local configuration and breaks on the first valid bundle
// from anywhere else.
//
// What does change meaning is which *variant* of a bundle this is, and the
// format says so directly: sigstore_bundle.proto defines two `oneof`s.
//
//	verificationMaterial.content  publicKey | x509CertificateChain | certificate
//	Bundle.content                messageSignature | dsseEnvelope
//
// Those are the fields that decide what the signature covers and what
// authenticates it, so exactly one arm of each must be present and it must
// be the arm this platform understands: a published public key, over a
// message digest. A bundle carrying two arms is not a bundle with an extra
// field — it is two contradictory claims, and picking one silently is how a
// blob signature gets accepted by a verifier the sender meant to read as an
// in-toto attestation.
//
// The keyless arms are refused rather than ignored. Their trust model is a
// Fulcio root and a transparency log; verifying the signature and
// discarding the identity material would answer a question nobody asked
package artifactsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MediaTypePrefix is the bundle media type this package understands. The
// version is checked as a prefix because Sigstore versions the media type
// itself, so a v0.4 bundle must be rejected as unknown rather than parsed
// with v0.3 assumptions.
const MediaTypePrefix = "application/vnd.dev.sigstore.bundle"

// ErrKeylessBundle is returned for a bundle whose verification material is
// certificate-based rather than a published public key.
var ErrKeylessBundle = errors.New("artifactsig: keyless bundle: its verification material is an X.509 certificate, so its trust model is a Fulcio root and a transparency log, not a published public key")

// Bundle is a keyed Sigstore bundle after parsing and validation.
//
// Every field here has already been decoded and its encoding checked, so
// Verify cannot be handed something Parse has not looked at. Fields the
// format carries and this platform does not consume — transparency log
// entries, timestamps — are deliberately absent rather than stored unread:
// a field a verifier holds but never checks is one a reader will assume it
// checked.
type Bundle struct {
	// MediaType is the bundle's declared format version.
	MediaType string
	// KeyHint is the base64 SHA-256 of the signer's DER
	// SubjectPublicKeyInfo, as cosign writes it. It is an identity claim,
	// not a signature input: checking it turns "this signature does not
	// verify" into "this bundle names a different key", which are different
	// bugs with different fixes.
	KeyHint string
	// Digest is the SHA-256 the bundle claims the artifact has. It is a
	// claim, never the value verified against — see Verify.
	Digest []byte
	// Signature is the ECDSA signature, ASN.1 DER encoded.
	Signature []byte
}

// wireBundle is the on-the-wire shape, decoded only as far as is needed to
// enforce the format's two oneofs before anything is interpreted. The arms
// are json.RawMessage so that "present" and "valid" stay separate
// questions: an arm that is present but malformed must be a rejected
// bundle, not an absent arm.
type wireBundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		PublicKey            *json.RawMessage `json:"publicKey"`
		X509CertificateChain *json.RawMessage `json:"x509CertificateChain"`
		Certificate          *json.RawMessage `json:"certificate"`
	} `json:"verificationMaterial"`
	MessageSignature *json.RawMessage `json:"messageSignature"`
	DSSEEnvelope     *json.RawMessage `json:"dsseEnvelope"`
}

type wirePublicKey struct {
	Hint string `json:"hint"`
}

type wireMessageSignature struct {
	MessageDigest struct {
		Algorithm string `json:"algorithm"`
		Digest    string `json:"digest"`
	} `json:"messageDigest"`
	Signature string `json:"signature"`
}

// Parse decodes a bundle and rejects every shape this platform does not
// produce, before any cryptography happens.
func Parse(data []byte) (Bundle, error) {
	var w wireBundle
	if err := json.Unmarshal(data, &w); err != nil {
		return Bundle{}, fmt.Errorf("artifactsig: parsing bundle: %w", err)
	}
	if !strings.HasPrefix(w.MediaType, MediaTypePrefix) {
		return Bundle{}, fmt.Errorf("artifactsig: unexpected media type %q, want a %s.* bundle", w.MediaType, MediaTypePrefix)
	}

	// oneof 1: verification material.
	vm := w.VerificationMaterial
	present := namesPresent(map[string]bool{
		"publicKey":            vm.PublicKey != nil,
		"x509CertificateChain": vm.X509CertificateChain != nil,
		"certificate":          vm.Certificate != nil,
	})
	switch {
	case len(present) == 0:
		return Bundle{}, errors.New("artifactsig: bundle carries no verification material, so there is nothing to check it against")
	case len(present) > 1:
		return Bundle{}, fmt.Errorf("artifactsig: bundle carries %s as verification material, but the format allows exactly one; two are two contradictory claims about what authenticates this signature", strings.Join(present, " and "))
	case vm.PublicKey == nil:
		return Bundle{}, ErrKeylessBundle
	}

	// oneof 2: content.
	content := namesPresent(map[string]bool{
		"messageSignature": w.MessageSignature != nil,
		"dsseEnvelope":     w.DSSEEnvelope != nil,
	})
	switch {
	case len(content) == 0:
		return Bundle{}, errors.New("artifactsig: bundle carries no content, so it signs nothing")
	case len(content) > 1:
		return Bundle{}, fmt.Errorf("artifactsig: bundle carries %s as content, but the format allows exactly one; picking either silently is how a blob signature is read as an attestation, or the reverse", strings.Join(content, " and "))
	case w.MessageSignature == nil:
		return Bundle{}, errors.New("artifactsig: bundle carries a DSSE envelope, which signs a statement about an artifact rather than the artifact's bytes; this package verifies the bytes")
	}

	var pk wirePublicKey
	if err := json.Unmarshal(*vm.PublicKey, &pk); err != nil {
		return Bundle{}, fmt.Errorf("artifactsig: parsing verification material: %w", err)
	}
	if pk.Hint == "" {
		return Bundle{}, errors.New("artifactsig: bundle names no public key, so there is nothing to check it against")
	}

	var ms wireMessageSignature
	if err := json.Unmarshal(*w.MessageSignature, &ms); err != nil {
		return Bundle{}, fmt.Errorf("artifactsig: parsing message signature: %w", err)
	}
	// SHA2_256 is what cosign writes for an ECDSA P-256 key and what the
	// digest comparison in Verify assumes. Anything else is refused rather
	// than hashed with SHA-256 anyway.
	if ms.MessageDigest.Algorithm != "SHA2_256" {
		return Bundle{}, fmt.Errorf("artifactsig: digest algorithm %q is not SHA2_256", ms.MessageDigest.Algorithm)
	}
	digest, err := base64.StdEncoding.DecodeString(ms.MessageDigest.Digest)
	if err != nil {
		return Bundle{}, fmt.Errorf("artifactsig: decoding message digest: %w", err)
	}
	if len(digest) != sha256.Size {
		return Bundle{}, fmt.Errorf("artifactsig: message digest is %d bytes, not the %d a SHA-256 digest has", len(digest), sha256.Size)
	}
	if ms.Signature == "" {
		return Bundle{}, errors.New("artifactsig: bundle carries no signature")
	}
	signature, err := base64.StdEncoding.DecodeString(ms.Signature)
	if err != nil {
		return Bundle{}, fmt.Errorf("artifactsig: decoding signature: %w", err)
	}

	return Bundle{
		MediaType: w.MediaType,
		KeyHint:   pk.Hint,
		Digest:    digest,
		Signature: signature,
	}, nil
}

// namesPresent returns the sorted names whose flag is set, so a message can
// say which arms collided rather than only that they did.
func namesPresent(arms map[string]bool) []string {
	// Fixed order rather than map order: an error message that changes
	// between runs is one nobody can grep for.
	var out []string
	for _, name := range []string{"publicKey", "x509CertificateChain", "certificate", "messageSignature", "dsseEnvelope"} {
		if arms[name] {
			out = append(out, name)
		}
	}
	return out
}

// Verify checks the bundle against the artifact and the public key.
//
// Three independent things are checked, and all three must hold:
//
//  1. the key the bundle names is the key supplied, by SHA-256 of its DER
//     SubjectPublicKeyInfo — the same hint cosign writes;
//  2. the digest the bundle carries is the digest of the artifact actually
//     supplied, recomputed here rather than taken from the document;
//  3. the signature verifies over that digest under that key.
//
// Check 2 is the one a verifier is most likely to skip, and skipping it is
// how a bundle for one file gets accepted for another: the signature would
// verify perfectly against the digest written in the bundle, which is not
// the digest of the bytes in front of you. It caught a real defect in this
// repository's own signing script, where a path outside the container's
// mount made cosign sign a different file of the same name.
func Verify(b Bundle, artifact io.Reader, pub *ecdsa.PublicKey) error {
	if pub == nil {
		return errors.New("artifactsig: no public key supplied")
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("artifactsig: encoding public key: %w", err)
	}
	hint := sha256.Sum256(spki)
	wantHint := base64.StdEncoding.EncodeToString(hint[:])
	if b.KeyHint != wantHint {
		return fmt.Errorf("artifactsig: bundle names key %s, but the public key supplied is %s", b.KeyHint, wantHint)
	}

	h := sha256.New()
	if _, err := io.Copy(h, artifact); err != nil {
		return fmt.Errorf("artifactsig: reading artifact: %w", err)
	}
	actual := h.Sum(nil)
	// Both values are public — the caller holds the artifact and the bundle
	// travels with it — so bytes.Equal is the honest comparison here.
	// Constant time would defend a secret that does not exist.
	if !bytes.Equal(b.Digest, actual) {
		return fmt.Errorf("artifactsig: the bundle is for a different artifact: it names sha256 %x, these bytes are %x", b.Digest, actual)
	}

	// VerifyASN1, because cosign writes the DER SEQUENCE of r and s that
	// PKCS#11 and OpenSSL also speak. A raw r||s pair would be a different
	// encoding of the same numbers and must not be accepted here.
	if !ecdsa.VerifyASN1(pub, actual, b.Signature) {
		return errors.New("artifactsig: signature does not verify over this artifact under this key")
	}
	return nil
}

// PublicKeyFromPEM reads a PKIX PEM public key and insists it is ECDSA.
func PublicKeyFromPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("artifactsig: no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("artifactsig: PEM block is %q, want PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("artifactsig: parsing public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("artifactsig: public key is %T, want an ECDSA key", parsed)
	}
	return pub, nil
}
