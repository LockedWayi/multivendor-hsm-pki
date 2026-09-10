// Package artifactsig verifies a keyed Sigstore signature bundle without
// Sigstore. It re-derives the answer from the standard library:
// crypto/sha256 over the artifact's bytes, crypto/ecdsa over the
// signature. A signature checked only by the tool that produced it shows
// that the tool agrees with itself.
//
// The parser is strict about the variant and tolerant of extra fields. A
// real Sigstore bundle carries tlogEntries and timestampVerificationData,
// so DisallowUnknownFields would refuse cosign's own release bundles. What
// changes meaning is which arm of each oneof is present:
//
//	verificationMaterial.content  publicKey | x509CertificateChain | certificate
//	Bundle.content                messageSignature | dsseEnvelope
//
// Exactly one arm of each must be present, and it must be the arm this
// platform understands: a published public key, over a message digest. Two
// arms are two contradictory claims. The keyless arms are refused: their
// trust model is a Fulcio root and a transparency log, and this package
// does not implement it.
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

// MediaTypePrefix is the bundle media type this package understands. A
// newer major version is rejected rather than parsed with old assumptions.
const MediaTypePrefix = "application/vnd.dev.sigstore.bundle"

// ErrKeylessBundle is returned for a bundle whose verification material is
// certificate-based rather than a published public key.
var ErrKeylessBundle = errors.New("artifactsig: keyless bundle: its verification material is an X.509 certificate, so its trust model is a Fulcio root and a transparency log, not a published public key")

// Bundle is a keyed Sigstore bundle after parsing. Fields the format
// carries and this platform does not consume are absent, so a reader
// cannot assume they were checked.
type Bundle struct {
	// MediaType is the bundle's declared format version.
	MediaType string
	// KeyHint is the base64 SHA-256 of the signer's DER
	// SubjectPublicKeyInfo, as cosign writes it. Checking it turns "does
	// not verify" into "names a different key".
	KeyHint string
	// Digest is the SHA-256 the bundle claims the artifact has. Verify
	// recomputes it; see there.
	Digest []byte
	// Signature is the ECDSA signature, ASN.1 DER encoded.
	Signature []byte
}

// wireBundle is the on-the-wire shape, decoded only far enough to enforce
// the two oneofs. The arms are json.RawMessage so that present and valid
// stay separate questions.
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
	// SHA2_256 is what cosign writes for an ECDSA P-256 key.
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

// namesPresent returns the names whose flag is set, in a fixed order so
// the error message is stable.
func namesPresent(arms map[string]bool) []string {
	var out []string
	for _, name := range []string{"publicKey", "x509CertificateChain", "certificate", "messageSignature", "dsseEnvelope"} {
		if arms[name] {
			out = append(out, name)
		}
	}
	return out
}

// Verify checks three things, and all three must hold: the key the bundle
// names is the key supplied, the digest the bundle carries is the digest
// of the artifact supplied, recomputed here, and the signature verifies
// over that digest under that key.
//
// The second check is the one a verifier skips most often. Without it, a
// bundle for one file is accepted for another. It caught a defect in this
// repository's signing script, where a path outside the container mount
// made cosign sign a different file of the same name.
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
	// Both values are public, so bytes.Equal is the right comparison.
	if !bytes.Equal(b.Digest, actual) {
		return fmt.Errorf("artifactsig: the bundle is for a different artifact: it names sha256 %x, these bytes are %x", b.Digest, actual)
	}

	// cosign writes the DER SEQUENCE of r and s. A raw r||s pair is a
	// different encoding and must not be accepted.
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
