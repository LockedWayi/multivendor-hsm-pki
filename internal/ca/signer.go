// Package ca implements the Certificate Authority: issuance, revocation
// and CRL generation, built on internal/pkcs11. The CA never holds raw key
// material; it asks a Signer to sign.
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// PINResolver returns the token's login PIN, read at the point of use (see
// config.Config.ResolvePIN) rather than cached anywhere with a longer
// lifetime than the call that needs it. It is used once, by Bootstrap, to
// establish the token login for the service's lifetime.
type PINResolver func() ([]byte, error)

// Signer is a crypto.Signer backed by an EC key pair on the token, reached
// through VendorAdapter. It never holds the private key. Every Sign call
// opens a session, asks the token to sign, and closes the session.
//
// It does not log in. Bootstrap authenticates the token once through
// LoginToken for the service's lifetime, and PKCS#11 authenticates the
// token for the whole application, so a session opened here can use
// private keys at once. See internal/pkcs11/tokenlogin.go.
//
// No session is held between calls. pkcs11.Session enforces an idle
// timeout and a maximum TTL and fails closed when either passes, so a
// session kept for the process lifetime would eventually fail every call.
//
// The private key object is looked up by CKA_LABEL in every session,
// rather than caching the handle GenerateKeyPair returned. SoftHSM2 2.6.1
// returned CKR_OBJECT_HANDLE_INVALID for a handle used after the session
// that obtained it was closed. PKCS#11 v2.40 scopes object handles to the
// application, not to one session, and guarantees a handle only for as
// long as the session that obtained it exists. So the SoftHSM2 behaviour
// may be implementation behaviour. A lookup per session works on every
// implementation, which is why the code does that.
type Signer struct {
	adapter     pk11.VendorAdapter
	workspace   pk11.Workspace
	sessionOpts pk11.SessionOptions

	keyLabel  string
	publicKey *ecdsa.PublicKey
	hash      crypto.Hash
}

// NewSigner builds a Signer over an existing HSM key pair, identified by
// the CKA_LABEL both halves of the pair were created with (KeyPairRequest.
// Label). curve must match the key pair's actual curve; it is used to
// reconstruct the public key from CKA_EC_POINT and to determine which hash
// algorithm Sign will accept (P-256 pairs with SHA-256, P-384 with
// SHA-384, P-521 with SHA-512, per FIPS 186-4's recommended curve/hash
// pairings).
//
// This opens one session to find the public key object and read its
// attributes, then closes it before returning; it does not keep a session
// open (see the Signer doc comment).
func NewSigner(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, keyLabel string, curve pk11.ECCurve) (*Signer, error) {
	ellipticCurve := curve.Curve()
	if ellipticCurve == nil {
		return nil, pk11.ErrUnsupportedCurve
	}
	hash, err := hashForCurve(curve)
	if err != nil {
		return nil, err
	}

	pub, err := withSession(ctx, adapter, ws, sessionOpts, func(s *pk11.Session) (*ecdsa.PublicKey, error) {
		handle, err := findKeyByLabel(ctx, adapter, s, pk11.ClassPublicKey, keyLabel)
		if err != nil {
			return nil, err
		}
		attrs, err := adapter.GetAttributes(ctx, s, handle, []pk11.AttributeType{pk11.AttrEcPoint})
		if err != nil {
			return nil, fmt.Errorf("ca: reading CKA_EC_POINT: %w", err)
		}
		if len(attrs) == 0 {
			return nil, fmt.Errorf("ca: CKA_EC_POINT not returned for public key %q", keyLabel)
		}
		return pk11.DecodeECPoint(ellipticCurve, attrs[0].Value)
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
// paired with this signer's curve (SHA-256 for P-256, and so on); any
// other hash function, or a digest of the wrong length for it, is rejected
// rather than sent to the HSM, so a mismatched caller fails loudly instead
// of producing a signature over the wrong bytes.
//
// The HSM returns a raw r||s ECDSA signature; Sign converts it to the
// ASN.1 DER SEQUENCE crypto/x509 expects before returning it.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != s.hash {
		return nil, fmt.Errorf("ca: signer requires hash %v for this curve, got %v", s.hash, opts.HashFunc())
	}
	if len(digest) != s.hash.Size() {
		return nil, fmt.Errorf("ca: digest is %d bytes, want %d for %v", len(digest), s.hash.Size(), s.hash)
	}

	ctx := context.Background()
	raw, err := withSession(ctx, s.adapter, s.workspace, s.sessionOpts, func(sess *pk11.Session) ([]byte, error) {
		handle, err := findKeyByLabel(ctx, s.adapter, sess, pk11.ClassPrivateKey, s.keyLabel)
		if err != nil {
			return nil, err
		}
		return s.adapter.Sign(ctx, sess, handle, pk11.Mechanism{Type: pk11.MechECDSA}, digest)
	})
	if err != nil {
		return nil, fmt.Errorf("ca: HSM sign: %w", err)
	}
	return rawECDSAToASN1(raw)
}

// hashForCurve returns the standard hash paired with curve (FIPS 186-4),
// or an error for a curve this package does not implement.
func hashForCurve(curve pk11.ECCurve) (crypto.Hash, error) {
	switch curve {
	case pk11.P256:
		return crypto.SHA256, nil
	case pk11.P384:
		return crypto.SHA384, nil
	case pk11.P521:
		return crypto.SHA512, nil
	default:
		return 0, pk11.ErrUnsupportedCurve
	}
}

// ecdsaASN1Signature is the ASN.1 SEQUENCE crypto/x509 expects an ECDSA
// signature to be encoded as (RFC 5480 / SEC1); PKCS#11's CKM_ECDSA
// produces the raw r||s concatenation instead.
type ecdsaASN1Signature struct {
	R, S *big.Int
}

// rawECDSAToASN1 converts a PKCS#11 raw r||s ECDSA signature (each half
// padded to the curve's byte length) into the ASN.1 DER SEQUENCE
// crypto/x509 expects.
func rawECDSAToASN1(sig []byte) ([]byte, error) {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, fmt.Errorf("ca: malformed raw ECDSA signature: %d bytes", len(sig))
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	sVal := new(big.Int).SetBytes(sig[half:])
	return asn1.Marshal(ecdsaASN1Signature{R: r, S: sVal})
}

// findKeyByLabel locates the single object of the given class and
// CKA_LABEL within session s. The lookup is done per session; the Signer
// comment says why a handle is not cached. The ambiguity rule lives in
// pkcs11.FindKeyByLabel. This wraps it so callers keep matching on
// ca.ErrKeyNotFound.
func findKeyByLabel(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, class pk11.ObjectClass, label string) (pk11.ObjectHandle, error) {
	handle, err := pk11.FindKeyByLabel(ctx, adapter, s, class, label)
	if errors.Is(err, pk11.ErrKeyNotFound) {
		return 0, fmt.Errorf("%w: class=%d label=%q", ErrKeyNotFound, class, label)
	}
	if err != nil {
		return 0, fmt.Errorf("ca: %w", err)
	}
	return handle, nil
}

// withSession opens a session against ws, runs fn, and closes the session.
//
// It does not log in. The token is already authenticated by Bootstrap's
// LoginToken. An earlier version logged in and out around every operation
// and failed under concurrency: the second caller's C_Login returned
// CKR_USER_ALREADY_LOGGED_IN, and the first caller's C_Logout
// de-authenticated the second one mid-signature.
//
// The zero value of T is returned with a non-nil error on any failure.
func withSession[T any](ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, opts pk11.SessionOptions, fn func(*pk11.Session) (T, error)) (T, error) {
	var zero T

	session, err := adapter.OpenSession(ctx, ws, opts)
	if err != nil {
		return zero, fmt.Errorf("ca: OpenSession: %w", err)
	}
	defer adapter.CloseSession(ctx, session)

	return fn(session)
}
