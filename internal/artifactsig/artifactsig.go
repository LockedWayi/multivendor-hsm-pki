// Package artifactsig verifies a Sigstore keyed signature bundle without
// Sigstore.
//
// # Why this exists
//
// Phase 4.9 signs the release binary with cosign over an HSM-held key. A
// verifier who reads that signature back with cosign learns only that
// cosign agrees with itself — the same closed loop that shipped a CRL Go
// could read and OpenSSL could not (docs/lessons.md §2), and a conformance
// suite that normalised away the property it tested (§3). CLAUDE.md §3.10
// is the rule that came out of both: what another implementation has to
// read is verified against another implementation.
//
// So this package re-derives the whole answer from the standard library —
// crypto/sha256 over the artifact's bytes, crypto/ecdsa over the signature
// — and shares no code with the tool that produced it. It is the same move
// Phase 1.5 made when it cross-checked HSM signatures against
// crypto/ecdsa rather than against the HSM.
//
// # What a keyed bundle is, and what this deliberately will not accept
//
// A Sigstore bundle comes in two shapes. The keyless one carries an
// ephemeral Fulcio certificate and is meaningless without a trust root and
// a transparency log. The keyed one carries only a hint naming the public
// key, and is exactly a detached signature over the artifact's SHA-256.
// This platform signs with a long-lived key published in a signed inventory
// (CLAUDE.md §3.7), so the keyed shape is the whole trust model and the
// keyless one is a different question wearing the same file extension.
//
// Handed a keyless bundle, this package fails rather than ignoring the
// certificate: silently verifying the signature and discarding the identity
// material would answer a question nobody asked (CLAUDE.md §3.4).
package artifactsig

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MediaTypePrefix is the bundle media type this package understands. The
// version is checked as a prefix because Sigstore versions the media type
// itself, so a v0.4 bundle must be rejected as unknown rather than parsed
// with v0.3 assumptions.
const MediaTypePrefix = "application/vnd.dev.sigstore.bundle"

// ErrKeylessBundle is returned for a bundle carrying certificate material.
var ErrKeylessBundle = errors.New("artifactsig: keyless bundle: it carries an X.509 certificate, so its trust model is a Fulcio root and a transparency log, not a published public key")

// Bundle is the subset of a Sigstore bundle a keyed signature uses.
//
// Only these fields are read. A field this platform does not verify is a
// field it must not appear to have checked, so the struct states the whole
// contract rather than embedding a general-purpose Sigstore type.
type Bundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		// Certificate is read only so its presence can be refused.
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate,omitempty"`
		PublicKey *struct {
			// Hint is the base64 SHA-256 of the signer's DER
			// SubjectPublicKeyInfo. It is an identity claim, not a
			// signature input: checking it turns "this signature does not
			// verify" into "this bundle names a different key", which are
			// different bugs with different fixes.
			Hint string `json:"hint"`
		} `json:"publicKey,omitempty"`
	} `json:"verificationMaterial"`
	MessageSignature struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    string `json:"digest"`
		} `json:"messageDigest"`
		Signature string `json:"signature"`
	} `json:"messageSignature"`
}

// Parse decodes a bundle and rejects every shape this platform does not
// produce, before any cryptography happens.
func Parse(data []byte) (Bundle, error) {
	var b Bundle
	dec := json.NewDecoder(newStrictReader(data))
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("artifactsig: parsing bundle: %w", err)
	}
	if !hasPrefix(b.MediaType, MediaTypePrefix) {
		return Bundle{}, fmt.Errorf("artifactsig: unexpected media type %q, want a %s.* bundle", b.MediaType, MediaTypePrefix)
	}
	if b.VerificationMaterial.Certificate != nil {
		return Bundle{}, ErrKeylessBundle
	}
	if b.VerificationMaterial.PublicKey == nil || b.VerificationMaterial.PublicKey.Hint == "" {
		return Bundle{}, errors.New("artifactsig: bundle names no public key, so there is nothing to check it against")
	}
	// SHA2_256 is what cosign writes for an ECDSA P-256 key and what the
	// digest comparison below assumes. Anything else is refused rather than
	// hashed with SHA-256 anyway.
	if got := b.MessageSignature.MessageDigest.Algorithm; got != "SHA2_256" {
		return Bundle{}, fmt.Errorf("artifactsig: digest algorithm %q is not SHA2_256", got)
	}
	if b.MessageSignature.Signature == "" {
		return Bundle{}, errors.New("artifactsig: bundle carries no signature")
	}
	return b, nil
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
// the digest of the bytes in front of you.
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
	if b.VerificationMaterial.PublicKey.Hint != wantHint {
		return fmt.Errorf("artifactsig: bundle names key %s, but the public key supplied is %s",
			b.VerificationMaterial.PublicKey.Hint, wantHint)
	}

	claimed, err := base64.StdEncoding.DecodeString(b.MessageSignature.MessageDigest.Digest)
	if err != nil {
		return fmt.Errorf("artifactsig: decoding message digest: %w", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, artifact); err != nil {
		return fmt.Errorf("artifactsig: reading artifact: %w", err)
	}
	actual := h.Sum(nil)
	if !equalConst(claimed, actual) {
		return fmt.Errorf("artifactsig: the bundle is for a different artifact: it names sha256 %x, these bytes are %x", claimed, actual)
	}

	sig, err := base64.StdEncoding.DecodeString(b.MessageSignature.Signature)
	if err != nil {
		return fmt.Errorf("artifactsig: decoding signature: %w", err)
	}
	// VerifyASN1, because cosign writes the DER SEQUENCE of r and s that
	// PKCS#11 and OpenSSL also speak. A raw r||s pair would be a different
	// encoding of the same numbers and must not be accepted here.
	if !ecdsa.VerifyASN1(pub, actual, sig) {
		return errors.New("artifactsig: signature does not verify over this artifact under this key")
	}
	return nil
}

// PublicKeyFromPEM reads a PKIX PEM public key and insists it is ECDSA.
func PublicKeyFromPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, err := firstPEMBlock(pemBytes)
	if err != nil {
		return nil, err
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
