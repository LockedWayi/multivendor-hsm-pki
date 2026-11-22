// Package ca implements the Certificate Authority: issuance, revocation
// and CRL generation, built on pkcs11. The CA never holds raw key
// material; it asks a Signer to sign.
package ca

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/pkcs11"
)

// PINResolver returns the token's login PIN, read at the point of use (see
// config.Config.ResolvePIN) rather than cached anywhere with a longer
// lifetime than the call that needs it. It is used once, by Bootstrap, to
// establish the token login for the service's lifetime.
type PINResolver func() ([]byte, error)

// Signer is the CA's crypto.Signer: a pkcs11.Signer over an EC key pair
// on the token, whose errors match on this package's ErrKeyNotFound. See
// pkcs11.Signer for how it reaches the key: it never holds the private
// key, does not log in (Bootstrap authenticates the token once through
// LoginToken), holds no session between calls and looks the key up by
// label in every session.
type Signer struct {
	inner *pk11.Signer
}

// NewSigner builds a Signer over an existing HSM key pair, identified by
// the CKA_LABEL both halves of the pair were created with. curve must
// match the key pair's actual curve; see pkcs11.NewSigner.
func NewSigner(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, keyLabel string, curve pk11.ECCurve) (*Signer, error) {
	inner, err := pk11.NewSigner(ctx, adapter, ws, sessionOpts, keyLabel, curve)
	if err != nil {
		return nil, keyNotFound(err)
	}
	return &Signer{inner: inner}, nil
}

// Public implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.inner.Public()
}

// Sign implements crypto.Signer; see pkcs11.Signer.Sign.
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.inner.Sign(rand, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("ca: HSM sign: %w", keyNotFound(err))
	}
	return sig, nil
}

// keyNotFound makes a missing key match ErrKeyNotFound as well as
// pkcs11.ErrKeyNotFound.
func keyNotFound(err error) error {
	if errors.Is(err, pk11.ErrKeyNotFound) && !errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("%w: %w", ErrKeyNotFound, err)
	}
	return err
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
