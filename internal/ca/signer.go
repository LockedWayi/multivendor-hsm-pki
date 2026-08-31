// Package ca implements the Certificate Authority logic — issuance,
// revocation, CRL generation — built on the Phase 1 internal/pkcs11 core.
// The CA never extracts its signing key from the HSM boundary: it asks a
// Signer to sign, and never holds raw key material itself
// (docs/phases/phase-2-ca-core.md).
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// PINResolver returns the token's login PIN, read at the point of use (see
// config.Config.ResolvePIN) rather than cached anywhere with a longer
// lifetime than the call that needs it. It is used once, by Bootstrap, to
// establish the token login for the service's lifetime.
type PINResolver func() ([]byte, error)

// Signer is a crypto.Signer backed by an HSM-resident EC key pair, reached
// through the Phase 1 VendorAdapter abstraction. It never holds the private
// key: every Sign call opens its own session, asks the HSM to sign, and
// closes the session again.
//
// It does not log in. The token is authenticated once by Bootstrap via
// LoginToken and stays that way for the service's lifetime, so the sessions
// opened here inherit that authentication — PKCS#11 authenticates a token
// for the whole application, not per session
// (internal/pkcs11/tokenlogin.go). An earlier version logged in and out
// around each operation and could not survive two concurrent requests; see
// withSession below for what that broke.
//
// A session is still not held between calls, deliberately: pkcs11.Session
// enforces an idle timeout and a maximum TTL and fails closed once either
// elapses (CLAUDE.md §3.4), so a signer reusing one session forever would
// eventually fail every call for a reason unrelated to the request. Those
// bounds govern a caller's session; the token's authentication is a
// separate lifetime, held by the adapter's anchor session, which is exactly
// why the two are no longer entangled.
//
// Signer looks the private key object up by its CKA_LABEL inside every
// session it opens, rather than caching the ObjectHandle GenerateKeyPair
// returned. Discovered empirically while building this type: a PKCS#11
// object handle for a CKA_TOKEN=true key is only valid within the session
// that obtained it — reusing a handle from the key-generation session in a
// different one fails CKR_OBJECT_HANDLE_INVALID (observed on SoftHSM2
// 2.6.1; recorded as a general PKCS#11 trap, not a vendor quirk, in
// docs/pkcs11-vendor-notes.md, since nothing here is SoftHSM2-specific
// behavior). A label-based re-lookup per session is the fix that generalizes
// to any vendor.
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
// Label). curve must match the key pair's actual curve — it is used to
// reconstruct the public key from CKA_EC_POINT and to determine which hash
// algorithm Sign will accept (P-256 pairs with SHA-256, P-384 with
// SHA-384, P-521 with SHA-512, per FIPS 186-4's recommended curve/hash
// pairings).
//
// This opens one session to find the public key object and read its
// attributes, then closes it before returning — it does not keep a session
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
// paired with this signer's curve (SHA-256 for P-256, and so on) — any
// other hash function, or a digest of the wrong length for it, is rejected
// rather than sent to the HSM, so a mismatched caller fails loudly instead
// of producing a signature over the wrong bytes (CLAUDE.md §3.4).
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
// produces the raw r||s concatenation instead (docs/pkcs11-vendor-notes.md).
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

// findKeyByLabel locates the single object of the given class with the
// given CKA_LABEL within session s. It exists because an ObjectHandle from
// one session is not valid in another — see the Signer doc comment — so
// every operation that needs a key handle finds it fresh, in its own
// session, rather than being handed one from elsewhere.
func findKeyByLabel(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, class pk11.ObjectClass, label string) (pk11.ObjectHandle, error) {
	handles, err := adapter.FindObjects(ctx, s, []pk11.Attribute{
		pk11.NumericAttribute(pk11.AttrClass, uint64(class)),
		{Type: pk11.AttrLabel, Value: []byte(label)},
	})
	if err != nil {
		return 0, fmt.Errorf("ca: FindObjects(class=%d, label=%q): %w", class, label, err)
	}
	switch len(handles) {
	case 0:
		return 0, fmt.Errorf("%w: class=%d label=%q", ErrKeyNotFound, class, label)
	case 1:
		return handles[0], nil
	default:
		return 0, fmt.Errorf("ca: %d objects found with class %d and label %q, want exactly 1", len(handles), class, label)
	}
}

// withSession opens a session against ws, runs fn, and closes the session
// afterward — the lifecycle every Signer operation shares.
//
// It does not log in, and that is the point. PKCS#11 authenticates a token
// for the whole application, not per session, so the token is already
// authenticated by the time this runs: Bootstrap established it once via
// LoginToken and it holds for the service's lifetime (see
// internal/pkcs11/tokenlogin.go). A session opened here inherits that
// authentication and can use private keys immediately.
//
// This used to log in and out around every operation. That was not merely
// wasteful, it was broken under concurrency: the second concurrent caller's
// C_Login failed with CKR_USER_ALREADY_LOGGED_IN, and the first caller's
// C_Logout de-authenticated the second one mid-signature. Serializing the
// calls could not fix it, because the interference happened between them.
//
// The zero value of T is returned alongside a non-nil error on any failure.
func withSession[T any](ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, opts pk11.SessionOptions, fn func(*pk11.Session) (T, error)) (T, error) {
	var zero T

	session, err := adapter.OpenSession(ctx, ws, opts)
	if err != nil {
		return zero, fmt.Errorf("ca: OpenSession: %w", err)
	}
	defer adapter.CloseSession(ctx, session)

	return fn(session)
}
