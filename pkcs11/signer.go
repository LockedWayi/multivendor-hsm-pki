package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
)

// Signer is a crypto.Signer backed by an EC key pair on a token, reached
// through a VendorAdapter. It never holds the private key. Every Sign call
// opens a session, asks the token to sign, and closes the session.
//
// It does not log in. Authenticate the token once with LoginToken before
// signing: PKCS#11 authenticates the token for the whole application, so
// a session opened here can use private keys at once. An earlier caller
// logged in and out around every operation and failed under concurrency:
// the second caller's C_Login returned CKR_USER_ALREADY_LOGGED_IN, and the
// first caller's C_Logout de-authenticated the second one mid-signature.
//
// No session is held between calls. Session enforces an idle timeout and a
// maximum TTL and fails closed when either passes, so a session kept for
// the process lifetime would eventually fail every call.
//
// The private key object is looked up by CKA_LABEL in every session,
// rather than caching a handle. PKCS#11 v2.40 guarantees a handle only for
// as long as the session that obtained it exists. The conformance suite
// measures what modules actually do (Capabilities.HandlesSpanSessions and
// .HandlesSurviveSessionClose), and every backend measured accepts a
// handle in both cases, but a lookup per session works whatever a module
// does. The lookup refuses a label that matches more than one object.
type Signer struct {
	adapter     VendorAdapter
	workspace   Workspace
	sessionOpts SessionOptions

	keyLabel  string
	publicKey *ecdsa.PublicKey
	hash      crypto.Hash
}

var _ crypto.Signer = (*Signer)(nil)

// NewSigner builds a Signer over an existing key pair in ws, identified by
// the CKA_LABEL both halves were created with (KeyPairRequest.Label).
// curve must match the pair's actual curve; it reconstructs the public key
// from CKA_EC_POINT and fixes the one hash Sign accepts (P-256 with
// SHA-256, P-384 with SHA-384, P-521 with SHA-512, the FIPS 186-4
// pairings).
//
// It opens one session to read the public key and closes it before
// returning. A missing key is ErrKeyNotFound, an ambiguous label
// ErrAmbiguousLabel.
func NewSigner(ctx context.Context, adapter VendorAdapter, ws Workspace, sessionOpts SessionOptions, keyLabel string, curve ECCurve) (*Signer, error) {
	ellipticCurve := curve.Curve()
	if ellipticCurve == nil {
		return nil, ErrUnsupportedCurve
	}
	hash, err := hashForCurve(curve)
	if err != nil {
		return nil, err
	}

	var pub *ecdsa.PublicKey
	err = inSession(ctx, adapter, ws, sessionOpts, func(s *Session) error {
		handle, err := FindKeyByLabel(ctx, adapter, s, ClassPublicKey, keyLabel)
		if err != nil {
			return err
		}
		attrs, err := adapter.GetAttributes(ctx, s, handle, []AttributeType{AttrEcPoint})
		if err != nil {
			return fmt.Errorf("pkcs11: reading CKA_EC_POINT: %w", err)
		}
		if len(attrs) == 0 {
			return fmt.Errorf("pkcs11: CKA_EC_POINT not returned for public key %q", keyLabel)
		}
		pub, err = DecodeECPoint(ellipticCurve, attrs[0].Value)
		return err
	})
	if err != nil {
		return nil, err
	}

	return &Signer{
		adapter:     adapter,
		workspace:   ws,
		sessionOpts: sessionOpts,
		keyLabel:    keyLabel,
		publicKey:   pub,
		hash:        hash,
	}, nil
}

// Public implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign implements crypto.Signer. digest must already be hashed with the
// algorithm opts.HashFunc() names, and that algorithm must be the one
// paired with this signer's curve; any other hash function, or a digest of
// the wrong length for it, is rejected rather than sent to the token, so a
// mismatched caller fails loudly instead of producing a signature over the
// wrong bytes.
//
// The token returns a raw r||s ECDSA signature; Sign converts it to the
// ASN.1 DER SEQUENCE crypto/x509 expects.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != s.hash {
		return nil, fmt.Errorf("pkcs11: signer requires hash %v for this curve, got %v", s.hash, opts.HashFunc())
	}
	if len(digest) != s.hash.Size() {
		return nil, fmt.Errorf("pkcs11: digest is %d bytes, want %d for %v", len(digest), s.hash.Size(), s.hash)
	}

	ctx := context.Background()
	var raw []byte
	err := inSession(ctx, s.adapter, s.workspace, s.sessionOpts, func(sess *Session) error {
		handle, err := FindKeyByLabel(ctx, s.adapter, sess, ClassPrivateKey, s.keyLabel)
		if err != nil {
			return err
		}
		raw, err = s.adapter.Sign(ctx, sess, handle, Mechanism{Type: MechECDSA}, digest)
		return err
	})
	if err != nil {
		return nil, err
	}
	return rawECDSAToASN1(raw)
}

// hashForCurve returns the standard hash paired with curve (FIPS 186-4),
// or an error for a curve this package does not implement.
func hashForCurve(curve ECCurve) (crypto.Hash, error) {
	switch curve {
	case P256:
		return crypto.SHA256, nil
	case P384:
		return crypto.SHA384, nil
	case P521:
		return crypto.SHA512, nil
	default:
		return 0, ErrUnsupportedCurve
	}
}

// ecdsaASN1Signature is the ASN.1 SEQUENCE crypto/x509 expects an ECDSA
// signature to be encoded as (RFC 5480 / SEC1); CKM_ECDSA produces the raw
// r||s concatenation instead.
type ecdsaASN1Signature struct {
	R, S *big.Int
}

// rawECDSAToASN1 converts a raw r||s ECDSA signature (each half padded to
// the curve's byte length) into the ASN.1 DER SEQUENCE crypto/x509
// expects.
func rawECDSAToASN1(sig []byte) ([]byte, error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, fmt.Errorf("pkcs11: malformed raw ECDSA signature: %d bytes", len(sig))
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	sVal := new(big.Int).SetBytes(sig[half:])
	return asn1.Marshal(ecdsaASN1Signature{R: r, S: sVal})
}

// inSession opens a session against ws, runs fn, and closes the session.
// It does not log in; see Signer.
func inSession(ctx context.Context, adapter VendorAdapter, ws Workspace, opts SessionOptions, fn func(*Session) error) error {
	session, err := adapter.OpenSession(ctx, ws, opts)
	if err != nil {
		return fmt.Errorf("pkcs11: OpenSession: %w", err)
	}
	defer adapter.CloseSession(ctx, session)
	return fn(session)
}
