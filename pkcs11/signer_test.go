package pkcs11_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/pkcs11"
)

// TestSigner runs pkcs11.Signer against every backend: a signature the
// token makes verifies under the public key NewSigner read back, and
// every input Sign must refuse is refused before it reaches the token.
func TestSigner(t *testing.T) {
	hsmtest.ForEachSingle(t, func(t *testing.T, s *hsmtest.Single) {
		ctx := context.Background()
		if err := s.Adapter.LoginToken(ctx, s.Workspace, append([]byte(nil), s.PIN...), s.Role.Role()); err != nil {
			t.Fatalf("LoginToken: %v", s.Role.Explain(err))
		}
		t.Cleanup(func() { _ = s.Adapter.LogoutToken(context.Background()) })

		newKey := func(t *testing.T, curve pk11.ECCurve, suffix string) string {
			t.Helper()
			label := "conf-" + s.RunID + "-" + suffix
			sess, err := s.Adapter.OpenSession(ctx, s.Workspace, pk11.SessionOptions{})
			if err != nil {
				t.Fatalf("OpenSession: %v", err)
			}
			defer s.Adapter.CloseSession(ctx, sess)
			kp, err := s.Adapter.GenerateKeyPair(ctx, sess, pk11.KeyPairRequest{Curve: curve, Label: label, Sign: true, Verify: true})
			if err != nil {
				t.Fatalf("GenerateKeyPair: %v", err)
			}
			t.Cleanup(func() {
				c := context.Background()
				sess, err := s.Adapter.OpenSession(c, s.Workspace, pk11.SessionOptions{})
				if err != nil {
					return
				}
				defer s.Adapter.CloseSession(c, sess)
				_ = s.Adapter.DestroyObject(c, sess, kp.Private)
				_ = s.Adapter.DestroyObject(c, sess, kp.Public)
			})
			return label
		}

		t.Run("P256_RoundTrip", func(t *testing.T) {
			signer, err := pk11.NewSigner(ctx, s.Adapter, s.Workspace, pk11.SessionOptions{}, newKey(t, pk11.P256, "signer-p256"), pk11.P256)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			digest := sha256.Sum256([]byte("pkcs11.Signer round trip, " + s.Name))
			sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			pub, ok := signer.Public().(*ecdsa.PublicKey)
			if !ok || !ecdsa.VerifyASN1(pub, digest[:], sig) {
				t.Fatal("the token's signature does not verify under the public key NewSigner read back")
			}
			tampered := digest
			tampered[0] ^= 0xff
			if ecdsa.VerifyASN1(pub, tampered[:], sig) {
				t.Fatal("the signature verifies over a different digest")
			}

			if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384); err == nil {
				t.Fatal("Sign accepted a hash that is not the curve's")
			}
			if _, err := signer.Sign(rand.Reader, digest[:16], crypto.SHA256); err == nil {
				t.Fatal("Sign accepted a digest of the wrong length")
			}
		})

		t.Run("P384_RoundTrip", func(t *testing.T) {
			signer, err := pk11.NewSigner(ctx, s.Adapter, s.Workspace, pk11.SessionOptions{}, newKey(t, pk11.P384, "signer-p384"), pk11.P384)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			digest := sha512.Sum384([]byte("pkcs11.Signer P-384, " + s.Name))
			sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !ecdsa.VerifyASN1(signer.Public().(*ecdsa.PublicKey), digest[:], sig) {
				t.Fatal("P-384 signature does not verify")
			}
		})

		t.Run("MissingKey", func(t *testing.T) {
			_, err := pk11.NewSigner(ctx, s.Adapter, s.Workspace, pk11.SessionOptions{}, "conf-"+s.RunID+"-no-such-key", pk11.P256)
			if !errors.Is(err, pk11.ErrKeyNotFound) {
				t.Fatalf("NewSigner over a missing key = %v, want ErrKeyNotFound", err)
			}
		})

		t.Run("UnsupportedCurve", func(t *testing.T) {
			_, err := pk11.NewSigner(ctx, s.Adapter, s.Workspace, pk11.SessionOptions{}, "unused", pk11.ECCurve(-1))
			if !errors.Is(err, pk11.ErrUnsupportedCurve) {
				t.Fatalf("NewSigner over an unknown curve = %v, want ErrUnsupportedCurve", err)
			}
		})
	})
}
