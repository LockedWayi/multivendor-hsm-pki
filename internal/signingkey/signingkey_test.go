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

// TestProvision_SatisfiesWhatCosignsBindingRequiresToFindThePair pins the
// preconditions cosign actually imposes, read out of its source rather than
// assumed (Phase 4.8).
//
// The chain, as of cosign v3.1.3 → ThalesIgnite/crypto11 v1.2.5:
//
//   - cosign passes *one* of keyID or keyLabel to crypto11's FindKeyPair
//     (keyID wins if both are configured), and that search matches the
//     **private** half.
//   - crypto11's makeKeyPair then reads CKA_ID and CKA_LABEL off that
//     private key and looks for the **public** half carrying both, falling
//     back to CKA_ID alone.
//   - A private key whose CKA_ID is empty is rejected outright with
//     errNoCkaId: "this is required to locate the matching public key".
//   - If no public half is found, no key pair is returned.
//
// So three things must hold on the token, and none of them is checked
// anywhere else in this repository: the private half has a non-empty
// CKA_ID, both halves carry the *same* CKA_ID, and both carry the same
// CKA_LABEL. A key that violates any of them is invisible to cosign while
// looking perfectly correct to every tool here — the signing step would fail
// with "no key pair found" for a key that plainly exists.
//
// This is the mechanical half of the check. Running cosign itself needs the
// pkcs11-enabled build, which Phase 4.9 obtains.
func TestProvision_SatisfiesWhatCosignsBindingRequiresToFindThePair(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)
		label := b.Label("image-signing-key-v4")

		if _, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: label}); err != nil {
			t.Fatalf("Provision: %v", err)
		}

		read := func(class pk11.ObjectClass) (id, lbl []byte) {
			t.Helper()
			h, err := pk11.FindKeyByLabel(ctx, b.Adapter, s, class, label)
			if err != nil {
				t.Fatalf("FindKeyByLabel(class=%d): %v", class, err)
			}
			attrs, err := b.Adapter.GetAttributes(ctx, s, h, []pk11.AttributeType{pk11.AttrID, pk11.AttrLabel})
			if err != nil {
				t.Fatalf("GetAttributes(class=%d): %v", class, err)
			}
			for _, a := range attrs {
				switch a.Type {
				case pk11.AttrID:
					id = a.Value
				case pk11.AttrLabel:
					lbl = a.Value
				}
			}
			return id, lbl
		}

		privID, privLabel := read(pk11.ClassPrivateKey)
		pubID, pubLabel := read(pk11.ClassPublicKey)

		if len(privID) == 0 {
			t.Error("the private key has an empty CKA_ID; crypto11 rejects such a key with errNoCkaId " +
				"before it ever looks for the public half")
		}
		if !bytes.Equal(privID, pubID) {
			t.Errorf("CKA_ID differs across the pair: private %x, public %x — crypto11 locates the public "+
				"half by the private half's CKA_ID, so cosign would report no key pair found", privID, pubID)
		}
		if !bytes.Equal(privLabel, pubLabel) {
			t.Errorf("CKA_LABEL differs across the pair: private %q, public %q — crypto11 matches on both "+
				"before falling back to CKA_ID alone", privLabel, pubLabel)
		}
		if string(privLabel) != label {
			t.Errorf("CKA_LABEL on the token is %q, want %q — this is the value a PKCS#11 URI's object= carries", privLabel, label)
		}
	})
}

// --- lateral and boundary cases around duplicate detection and key naming ---

// TestFindDuplicateKey_SeesAKeyUnderAnotherLabelAndSkipsItsOwn exercises the
// comparison directly, because the path that triggers it in Provision cannot
// be arranged on a backend whose RNG works.
//
// Both halves matter. Missing a genuine duplicate is the defect the check
// exists for; *reporting* the key against itself would make every
// provisioning fail, so the guard has to distinguish "another object holds
// my key" from "I am on the token".
func TestFindDuplicateKey_SeesAKeyUnderAnotherLabelAndSkipsItsOwn(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)
		label := b.Label("image-signing-key-v5")

		key, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: label})
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}

		// Asked from the point of view of a hypothetical second key: this
		// public point is already on the token, under `label`.
		found, err := signingkey.FindDuplicateKey(ctx, b.Adapter, s, b.Label("artifact-signing-key-v5"), key.Public, pk11.P256)
		if err != nil {
			t.Fatalf("FindDuplicateKey: %v", err)
		}
		if found != label {
			t.Errorf("FindDuplicateKey = %q, want %q — a duplicate under another label went unnoticed", found, label)
		}

		// Asked from the point of view of the key itself: not a duplicate.
		found, err = signingkey.FindDuplicateKey(ctx, b.Adapter, s, label, key.Public, pk11.P256)
		if err != nil {
			t.Fatalf("FindDuplicateKey: %v", err)
		}
		if found != "" {
			t.Errorf("FindDuplicateKey reported %q against the key's own label; every provisioning would fail", found)
		}
	})
}

// TestFindDuplicateKey_DoesNotMatchAcrossCurves pins that a key on another
// curve is skipped rather than mistaken for a match or turned into an error.
// A token holding P-384 keys for some other purpose must not make P-256
// provisioning unusable.
func TestFindDuplicateKey_DoesNotMatchAcrossCurves(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)

		if _, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{
			Label: b.Label("artifact-signing-key-v6"),
			Curve: pk11.P384,
		}); err != nil {
			t.Skipf("this backend did not provision a P-384 key (%v); the cross-curve case cannot be exercised here", err)
		}
		p256, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: b.Label("image-signing-key-v6")})
		if err != nil {
			t.Fatalf("Provision P-256: %v", err)
		}

		found, err := signingkey.FindDuplicateKey(ctx, b.Adapter, s, b.Label("image-signing-key-v7"), p256.Public, pk11.P256)
		if err != nil {
			t.Fatalf("FindDuplicateKey with a P-384 key on the token: %v", err)
		}
		if found != b.Label("image-signing-key-v6") {
			t.Errorf("FindDuplicateKey = %q, want the P-256 key; a key on another curve must be skipped, not confused with it", found)
		}
	})
}

// TestProvision_LabelRoundTripsExactly pins that what the token stores is
// what was asked for, byte for byte.
//
// It is the precondition for every label-based lookup in this repository and
// for cosign's PKCS#11 URI, whose `object=` carries exactly this string. A
// token that padded CKA_LABEL to a fixed width, or truncated it, would leave
// keys that this platform creates and then cannot find — and the failure
// would read as "no key pair found" for a key plainly on the token.
func TestProvision_LabelRoundTripsExactly(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)
		label := b.Label("artifact-signing-key-v7")

		if _, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: label}); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		for _, class := range []pk11.ObjectClass{pk11.ClassPublicKey, pk11.ClassPrivateKey} {
			h, err := pk11.FindKeyByLabel(ctx, b.Adapter, s, class, label)
			if err != nil {
				t.Fatalf("FindKeyByLabel(class=%d): %v", class, err)
			}
			attrs, err := b.Adapter.GetAttributes(ctx, s, h, []pk11.AttributeType{pk11.AttrLabel})
			if err != nil {
				t.Fatalf("GetAttributes: %v", err)
			}
			if got := string(attrs[0].Value); got != label {
				t.Errorf("class %d: CKA_LABEL round-tripped as %q (%d bytes), want %q (%d bytes)",
					class, got, len(got), label, len(label))
			}
		}
	})
}

// TestProvision_LabelLookupIsExactNotAPrefixMatch is the boundary case
// versioned labels create for themselves: `-v1` is a prefix of `-v10`, and
// they are different keys with different lifecycle states.
//
// A token that prefix-matched would return two objects for `-v1` — caught by
// FindKeyByLabel's ambiguity refusal — or, worse, the wrong one. Either way a
// verify-only key and an active key would be indistinguishable by the only
// name a PKCS#11 URI can carry.
func TestProvision_LabelLookupIsExactNotAPrefixMatch(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)
		short := b.Label("image-signing-key-v1")
		long := b.Label("image-signing-key-v10")

		shortKey, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: short})
		if err != nil {
			t.Fatalf("Provision %s: %v", short, err)
		}
		longKey, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: long})
		if err != nil {
			t.Fatalf("Provision %s: %v", long, err)
		}
		if signingkey.SameKey(shortKey.Public, longKey.Public) {
			t.Fatal("the two versions are the same key pair")
		}

		// Each label must resolve to its own key, not to the other and not
		// to both.
		gotShort, err := signingkey.Load(ctx, b.Adapter, s, short, pk11.P256)
		if err != nil {
			t.Fatalf("Load %s: %v", short, err)
		}
		if !signingkey.SameKey(gotShort.Public, shortKey.Public) {
			t.Errorf("%q resolved to a different key — a prefix match would do exactly this", short)
		}
		gotLong, err := signingkey.Load(ctx, b.Adapter, s, long, pk11.P256)
		if err != nil {
			t.Fatalf("Load %s: %v", long, err)
		}
		if !signingkey.SameKey(gotLong.Public, longKey.Public) {
			t.Errorf("%q resolved to a different key", long)
		}

		// And the label of the shorter one must still count as taken, so a
		// second provisioning under it cannot succeed.
		if _, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: short}); !errors.Is(err, signingkey.ErrLabelTaken) {
			t.Errorf("re-provisioning %q = %v, want ErrLabelTaken", short, err)
		}
	})
}

// TestProvision_DistinctKeysGetDistinctCKAIDs matters because of how cosign
// resolves a key: crypto11 takes CKA_ID as authoritative and, when cosign is
// configured with an id, uses it in preference to the label. Two keys
// sharing an id would make that lookup ambiguous in a way no label check
// could see.
func TestProvision_DistinctKeysGetDistinctCKAIDs(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		s := session(t, b)

		readID := func(label string) []byte {
			t.Helper()
			h, err := pk11.FindKeyByLabel(ctx, b.Adapter, s, pk11.ClassPrivateKey, label)
			if err != nil {
				t.Fatalf("FindKeyByLabel(%s): %v", label, err)
			}
			attrs, err := b.Adapter.GetAttributes(ctx, s, h, []pk11.AttributeType{pk11.AttrID})
			if err != nil {
				t.Fatalf("GetAttributes(%s): %v", label, err)
			}
			return attrs[0].Value
		}

		image := b.Label("image-signing-key-v8")
		artifact := b.Label("artifact-signing-key-v8")
		for _, label := range []string{image, artifact} {
			if _, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: label}); err != nil {
				t.Fatalf("Provision(%s): %v", label, err)
			}
		}

		imageID, artifactID := readID(image), readID(artifact)
		if len(imageID) == 0 || len(artifactID) == 0 {
			t.Fatal("a signing key has an empty CKA_ID; crypto11 rejects such a key outright")
		}
		if bytes.Equal(imageID, artifactID) {
			t.Errorf("the image and artifact keys share CKA_ID %x — cosign resolves by id in preference to label, "+
				"so the two purposes would be indistinguishable to it", imageID)
		}
	})
}
