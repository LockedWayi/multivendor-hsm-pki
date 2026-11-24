package main

import (
	"context"
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/pkcs11"
)

// TestSurvey_SeesEveryKeyClassTheSuiteLeaves: a run killed mid-way leaves
// key pairs and the conformance suite's AES keys. Before the fix the
// survey listed only key pairs, so a "zero objects left" reading was
// blind to secret keys, and -confirm never removed them.
func TestSurvey_SeesEveryKeyClassTheSuiteLeaves(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s, err := b.Adapter.OpenSession(ctx, b.Primary, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer func() { _ = b.Adapter.CloseSession(ctx, s) }()
		if err := b.Adapter.Login(ctx, s, []byte(b.PrimaryPIN), b.Role.Role()); err != nil {
			t.Fatalf("Login: %v", err)
		}
		defer func() { _ = b.Adapter.LogoutToken(ctx) }()

		pairLabel, secretLabel := b.Label("litter-pair"), b.Label("litter-aes")
		if _, err := b.Adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{Curve: pk11.P256, Label: pairLabel, Sign: true, Verify: true}); err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		if _, err := b.Adapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{Label: secretLabel, Encrypt: true, Decrypt: true}); err != nil {
			t.Fatalf("GenerateSecretKey: %v", err)
		}

		_, matched, err := survey(ctx, b.Adapter, s, "t-"+b.RunID+"-litter-")
		if err != nil {
			t.Fatalf("survey: %v", err)
		}
		seen := map[pk11.ObjectClass]int{}
		for _, o := range matched {
			seen[o.class]++
		}
		for _, class := range []pk11.ObjectClass{pk11.ClassPublicKey, pk11.ClassPrivateKey, pk11.ClassSecretKey} {
			if seen[class] != 1 {
				t.Errorf("survey found %d objects of class %d with the prefix, want 1 (all matched: %+v)", seen[class], class, matched)
			}
		}
	})
}
