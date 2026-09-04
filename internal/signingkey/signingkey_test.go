package signingkey_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/LockedWayi/hsm-pki-platform/internal/hsmtest"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
	"github.com/LockedWayi/hsm-pki-platform/internal/signingkey"
)

// These tests reach a token, so every one of them runs against every
// backend the environment provides (CLAUDE.md §2.4). The pure-logic ones —
// label shape, public-key comparison — are at the bottom and deliberately
// do not multiply.

// session opens a logged-in session on the backend's primary token.
func session(t *testing.T, b *hsmtest.Backend) *pk11.Session {
	t.Helper()
	ctx := context.Background()
	s, err := b.Adapter.OpenSession(ctx, b.Primary, pk11.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = b.Adapter.CloseSession(context.Background(), s) })
	if err := b.Adapter.Login(ctx, s, []byte(b.PrimaryPIN), pk11.RoleUser); err != nil {
		t.Fatalf("Login: %v", err)
	}
	t.Cleanup(func() { _ = b.Adapter.LogoutToken(context.Background()) })
	return s
}

func TestProvision_ProducesAProtectedSigningKey(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)

		key, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{
			Label: b.Label("image-signing-key-v1"),
		})
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}

		// Read off the token, not echoed back from the request. This is the
		// assertion that would have caught the CKA_SENSITIVE defect
		// (docs/lessons.md §1).
		if !key.Sensitive {
			t.Error("CKA_SENSITIVE is false on the token; the private key can be read out")
		}
		if key.Extractable {
			t.Error("CKA_EXTRACTABLE is true on the token; the private key can be wrapped off it")
		}
		if key.Public == nil || key.Public.Curve != elliptic.P256() {
			t.Fatalf("public key = %v, want a P-256 key", key.Public)
		}
	})
}

func TestProvision_KeyIsUsableForSigningAndVerifiesInTheStandardLibrary(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)
		label := b.Label("artifact-signing-key-v1")

		key, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: label})
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}

		// A signing key that cannot sign is not a signing key, and a
		// signature only this repository can verify is not a signature. So
		// the HSM signs and crypto/ecdsa checks it — the same cross-check
		// Phase 1.5 made against the HSM itself, and the one Phase 4.9 will
		// make against cosign.
		priv, err := pk11.FindKeyByLabel(ctx, b.Adapter, s, pk11.ClassPrivateKey, label)
		if err != nil {
			t.Fatalf("FindKeyByLabel: %v", err)
		}
		digest := sha256.Sum256([]byte("release artifact bytes"))
		sig, err := b.Adapter.Sign(ctx, s, priv, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:])
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		// PKCS#11 returns raw r||s, not DER (docs/pkcs11-vendor-notes.md).
		if len(sig)%2 != 0 {
			t.Fatalf("signature length %d is odd; expected r||s", len(sig))
		}
		half := len(sig) / 2
		r := new(big.Int).SetBytes(sig[:half])
		sVal := new(big.Int).SetBytes(sig[half:])
		if !ecdsa.Verify(key.Public, digest[:], r, sVal) {
			t.Error("crypto/ecdsa rejected a signature the HSM produced with this key")
		}
	})
}

func TestProvision_RefusesALabelAlreadyInUse(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)
		label := b.Label("image-signing-key-v1")

		if _, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: label}); err != nil {
			t.Fatalf("first Provision: %v", err)
		}
		// The second must refuse rather than add a second object under the
		// same label: that would manufacture exactly the ambiguity
		// FindKeyByLabel exists to reject, and leave which key signs to
		// enumeration order.
		_, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: label})
		if !errors.Is(err, signingkey.ErrLabelTaken) {
			t.Fatalf("second Provision error = %v, want ErrLabelTaken", err)
		}
	})
}

func TestProvision_TwoKeysAreGenuinelyDifferentKeys(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)

		image, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{
			Label: b.Label("image-signing-key-v1"),
		})
		if err != nil {
			t.Fatalf("Provision image key: %v", err)
		}
		artifact, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{
			Label: b.Label("artifact-signing-key-v1"),
		})
		if err != nil {
			t.Fatalf("Provision artifact key: %v", err)
		}

		// Distinct labels prove nothing — two labels can name one key pair,
		// which is the reuse CLAUDE.md §3.6 forbids and the thing a label
		// comparison cannot see. Compare the public points.
		if signingkey.SameKey(image.Public, artifact.Public) {
			t.Error("the image and artifact keys are the same key pair under two labels")
		}
	})
}

func TestProvision_RejectsAnUnversionedLabelBeforeTouchingTheToken(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)

		// "image-signing-key" with no version. Rejected because rotation
		// under a bare label is a breaking rename for every consumer
		// (CLAUDE.md §3.7), and because a parameter error must surface
		// before an irreversible generation, not after (§3.9).
		bad := b.Label("image-signing-key")
		if _, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: bad}); err == nil {
			t.Fatal("Provision accepted an unversioned label")
		}
		// And nothing was created under it.
		if _, err := pk11.FindKeyByLabel(ctx, b.Adapter, s, pk11.ClassPrivateKey, bad); !errors.Is(err, pk11.ErrKeyNotFound) {
			t.Fatalf("after a rejected label, FindKeyByLabel = %v, want ErrKeyNotFound", err)
		}
	})
}

func TestVerify_ReportsWhatTheTokenSaysAboutAnExistingKey(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)
		label := b.Label("image-signing-key-v2")

		provisioned, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: label})
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		loaded, err := signingkey.Verify(ctx, b.Adapter, s, label, pk11.P256)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !signingkey.SameKey(provisioned.Public, loaded.Public) {
			t.Error("Verify returned a different public key than Provision did")
		}
	})
}

func TestVerify_FailsClosedOnAnAbsentKey(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)
		_, err := signingkey.Verify(ctx, b.Adapter, s, b.Label("never-provisioned-v1"), pk11.P256)
		if !errors.Is(err, pk11.ErrKeyNotFound) {
			t.Fatalf("Verify on an absent key = %v, want ErrKeyNotFound", err)
		}
	})
}

func TestKeyPEM_IsReadableByAVerifierWithNoHSM(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)

		key, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{
			Label: b.Label("artifact-signing-key-v2"),
		})
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		out, err := key.PEM()
		if err != nil {
			t.Fatalf("PEM: %v", err)
		}

		// Parsed back through the standard library's generic PEM/PKIX path,
		// which is what any verifier — cosign included — will use. Decoding
		// it with something that knows how we wrote it would prove nothing
		// (CLAUDE.md §3.10).
		block, rest := pem.Decode(out)
		if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
			t.Fatalf("PEM output is not a single PUBLIC KEY block: %q", out)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("ParsePKIXPublicKey: %v", err)
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("parsed public key is %T, want *ecdsa.PublicKey", parsed)
		}
		if !signingkey.SameKey(pub, key.Public) {
			t.Error("the exported PEM is a different key than the one on the token")
		}

		// And it carries no private material, which is the whole reason a
		// verifier can hold it.
		if bytes.Contains(out, []byte("PRIVATE")) {
			t.Error("exported PEM mentions PRIVATE")
		}
	})
}

// TestCheckNoCAHierarchyKey_PassesOnATokenWithoutCAKeys pins the case that
// must not become a false refusal: the guard is run before every
// provisioning, so a token carrying only supply-chain keys has to clear it.
func TestCheckNoCAHierarchyKey_PassesOnATokenWithoutCAKeys(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)

		if _, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{
			Label: b.Label("image-signing-key-v3"),
		}); err != nil {
			t.Fatalf("Provision: %v", err)
		}

		if err := signingkey.CheckNoCAHierarchyKey(ctx, b.Adapter, s); err != nil {
			t.Fatalf("CheckNoCAHierarchyKey on a supply-chain token = %v, want nil", err)
		}
	})
}

// TestCheckNoCAHierarchyKey_RefusesATokenHoldingACAKey is Phase 4.8's
// third-token decision as an assertion. Every object involved is
// individually correct — the CA key is a well-formed CA key, the signing
// key would be a well-formed signing key — and the defect is only that they
// share a token, which is exactly the kind of thing no per-object check can
// see (docs/threat-model.md §6.1).
func TestCheckNoCAHierarchyKey_RefusesATokenHoldingACAKey(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)

		// A real key pair rather than a stub object: the guard reads labels
		// off private keys the token actually holds, so a test that faked
		// one would be testing something else.
		caLabel := b.Label("ca-intermediate-key-v1")
		if _, err := b.Adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: caLabel, Sign: true, Verify: true,
		}); err != nil {
			t.Fatalf("GenerateKeyPair(%s): %v", caLabel, err)
		}

		err := signingkey.CheckNoCAHierarchyKey(ctx, b.Adapter, s)
		if !errors.Is(err, signingkey.ErrCAHierarchyKeyPresent) {
			t.Fatalf("CheckNoCAHierarchyKey on the CA's token = %v, want ErrCAHierarchyKeyPresent", err)
		}
		// The operator has to be told which object caused the refusal;
		// "wrong token" with no name in it is not actionable on a token
		// holding hundreds of keys.
		if !strings.Contains(err.Error(), caLabel) {
			t.Errorf("refusal does not name the offending key: %v", err)
		}
	})
}

// --- pure logic below: no token, so these do not multiply per backend ---

func TestSameKey(t *testing.T) {
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if !signingkey.SameKey(&a.PublicKey, &a.PublicKey) {
		t.Error("SameKey said a key differs from itself")
	}
	if signingkey.SameKey(&a.PublicKey, &b.PublicKey) {
		t.Error("SameKey said two independent keys are the same")
	}
	if signingkey.SameKey(nil, &a.PublicKey) || signingkey.SameKey(&a.PublicKey, nil) {
		t.Error("SameKey treated nil as equal to a key")
	}
}

func TestValidateLabel(t *testing.T) {
	// Versioning is what makes rotation a lifecycle step rather than a
	// breaking rename (CLAUDE.md §3.7), so an unversioned label is refused
	// rather than defaulted to -v1: a tool that silently picks a version
	// for you is a tool that will pick the same one twice.
	valid := []string{"image-signing-key-v1", "artifact-signing-key-v12", "audit-signing-key-v1"}
	for _, label := range valid {
		if err := signingkey.ValidateLabel(label); err != nil {
			t.Errorf("ValidateLabel(%q) = %v, want nil", label, err)
		}
	}
	invalid := []string{
		"",                      // nothing at all
		"image-signing-key",     // the case the rule exists for
		"image-signing-key-v",   // a version marker with no version
		"Image-Signing-Key-v1",  // labels are lower case, so two spellings cannot both address one key
		"image signing key v1",  // a space would have to be quoted in every PKCS#11 URI that carries it
		"image-signing-key-v1x", // trailing junk after the version
	}
	for _, label := range invalid {
		if err := signingkey.ValidateLabel(label); err == nil {
			t.Errorf("ValidateLabel(%q) = nil, want an error", label)
		}
	}
}
