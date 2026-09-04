package artifactsig_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LockedWayi/hsm-pki-platform/internal/artifactsig"
)

// The fixture is a real cosign v3.1.3 signature, made over the HSM with
// artifact-signing-key-v1 on the supply-chain token and a signing config
// carrying no transparency log. That is the point of it: a test that signed
// its own vector with crypto/ecdsa and then verified it would prove this
// package agrees with itself, which it would do just as convincingly if the
// bundle format were wrong (CLAUDE.md §3.10, docs/lessons.md §2).
//
// It is verified against docs/keys/artifact-signing-key-v1.pub -- the file
// this repository publishes -- so a published key that stopped matching the
// token would fail here. If the artifact key is ever rotated, this fixture
// keeps verifying under the -v1 key while it is verify-only, and is
// re-signed when that version retires.
const (
	fixtureArtifact = "testdata/sample-artifact.txt"
	fixtureBundle   = "testdata/sample-artifact.bundle"
	publishedKey    = "../../docs/keys/artifact-signing-key-v1.pub"
	otherPurposeKey = "../../docs/keys/image-signing-key-v1.pub"
)

func loadKey(t *testing.T, path string) *ecdsa.PublicKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	pub, err := artifactsig.PublicKeyFromPEM(data)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return pub
}

func loadFixture(t *testing.T) (artifactsig.Bundle, []byte) {
	t.Helper()
	raw, err := os.ReadFile(fixtureBundle)
	if err != nil {
		t.Fatalf("reading bundle: %v", err)
	}
	b, err := artifactsig.Parse(raw)
	if err != nil {
		t.Fatalf("parsing bundle: %v", err)
	}
	artifact, err := os.ReadFile(fixtureArtifact)
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}
	return b, artifact
}

// rewrite re-encodes the fixture bundle with one field replaced, so the
// negative cases differ from the positive one in exactly one way.
func rewrite(t *testing.T, mutate func(m map[string]any)) []byte {
	t.Helper()
	raw, err := os.ReadFile(fixtureBundle)
	if err != nil {
		t.Fatalf("reading bundle: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshalling bundle: %v", err)
	}
	mutate(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshalling bundle: %v", err)
	}
	return out
}

func TestVerify_AcceptsARealCosignSignatureOverTheHSMKey(t *testing.T) {
	b, artifact := loadFixture(t)
	if err := artifactsig.Verify(b, bytes.NewReader(artifact), loadKey(t, publishedKey)); err != nil {
		t.Fatalf("a genuine cosign signature was rejected: %v", err)
	}
}

func TestVerify_RejectsASingleFlippedBit(t *testing.T) {
	b, artifact := loadFixture(t)
	corrupted := append([]byte(nil), artifact...)
	corrupted[len(corrupted)/2] ^= 0x01
	err := artifactsig.Verify(b, bytes.NewReader(corrupted), loadKey(t, publishedKey))
	if err == nil {
		t.Fatal("a corrupted artifact verified")
	}
	// The digest comparison must be what catches it, not the signature
	// check: "this bundle is for a different artifact" and "this signature
	// is forged" are different findings, and reporting the wrong one sends
	// whoever reads it looking in the wrong place.
	if !strings.Contains(err.Error(), "different artifact") {
		t.Fatalf("wrong failure reported: %v", err)
	}
}

func TestVerify_RejectsTheOtherPurposesKey(t *testing.T) {
	// Purpose separation is only real if a verifier can express it. The
	// image key must not verify an artifact signature (CLAUDE.md §3.6).
	b, artifact := loadFixture(t)
	err := artifactsig.Verify(b, bytes.NewReader(artifact), loadKey(t, otherPurposeKey))
	if err == nil {
		t.Fatal("the image-signing key verified an artifact signature")
	}
	if !strings.Contains(err.Error(), "names key") {
		t.Fatalf("wrong failure reported: %v", err)
	}
}

func TestVerify_RejectsADigestEditedToMatchOtherBytes(t *testing.T) {
	// The attack this closes: take a genuine bundle, point it at different
	// content by rewriting the digest it claims. A verifier that trusts the
	// document's digest instead of recomputing it accepts this.
	b, artifact := loadFixture(t)
	other := append([]byte(nil), artifact...)
	other = append(other, []byte("appended by somebody else\n")...)

	raw := rewrite(t, func(m map[string]any) {
		ms := m["messageSignature"].(map[string]any)
		md := ms["messageDigest"].(map[string]any)
		sum := sha256Of(other)
		md["digest"] = base64.StdEncoding.EncodeToString(sum)
	})
	edited, err := artifactsig.Parse(raw)
	if err != nil {
		t.Fatalf("parsing edited bundle: %v", err)
	}
	if err := artifactsig.Verify(edited, bytes.NewReader(other), loadKey(t, publishedKey)); err == nil {
		t.Fatal("a bundle whose digest was edited to match other bytes verified")
	}
	// And the original still verifies, so the test above failed for the
	// right reason rather than because the rewrite broke the bundle.
	if err := artifactsig.Verify(b, bytes.NewReader(artifact), loadKey(t, publishedKey)); err != nil {
		t.Fatalf("the untouched bundle stopped verifying: %v", err)
	}
}

func TestVerify_RejectsARawSignatureInsteadOfASN1(t *testing.T) {
	// r||s and the DER SEQUENCE of r and s are the same two numbers in two
	// encodings. PKCS#11, OpenSSL and cosign speak DER here, so accepting
	// the raw form would be this package quietly widening an interop
	// contract it does not own.
	b, artifact := loadFixture(t)
	der, err := base64.StdEncoding.DecodeString(b.MessageSignature.Signature)
	if err != nil {
		t.Fatalf("decoding fixture signature: %v", err)
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatalf("the fixture signature is not a DER SEQUENCE of r and s: %v", err)
	}
	raw := make([]byte, 64)
	parsed.R.FillBytes(raw[:32])
	parsed.S.FillBytes(raw[32:])

	rewritten := rewrite(t, func(m map[string]any) {
		ms := m["messageSignature"].(map[string]any)
		ms["signature"] = base64.StdEncoding.EncodeToString(raw)
	})
	rawBundle, err := artifactsig.Parse(rewritten)
	if err != nil {
		t.Fatalf("parsing rewritten bundle: %v", err)
	}
	if err := artifactsig.Verify(rawBundle, bytes.NewReader(artifact), loadKey(t, publishedKey)); err == nil {
		t.Fatal("a raw r||s signature was accepted where DER is the contract")
	}
}

func TestParse_RefusesTheShapesThisPlatformDoesNotProduce(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{
			// A keyless bundle's trust model is a Fulcio root and a
			// transparency log. Verifying its signature and discarding the
			// certificate would answer a question nobody asked.
			name: "keyless bundle carrying a certificate",
			mutate: func(m map[string]any) {
				vm := m["verificationMaterial"].(map[string]any)
				vm["certificate"] = map[string]any{"rawBytes": "AAAA"}
			},
			want: "keyless bundle",
		},
		{
			name: "a media type from some future version",
			mutate: func(m map[string]any) {
				m["mediaType"] = "application/vnd.example.something+json"
			},
			want: "unexpected media type",
		},
		{
			name: "a digest algorithm that is not SHA2_256",
			mutate: func(m map[string]any) {
				md := m["messageSignature"].(map[string]any)["messageDigest"].(map[string]any)
				md["algorithm"] = "SHA2_512"
			},
			want: "not SHA2_256",
		},
		{
			name: "no public key named at all",
			mutate: func(m map[string]any) {
				m["verificationMaterial"] = map[string]any{}
			},
			want: "names no public key",
		},
		{
			name: "no signature",
			mutate: func(m map[string]any) {
				m["messageSignature"].(map[string]any)["signature"] = ""
			},
			want: "no signature",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := artifactsig.Parse(rewrite(t, tc.mutate))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong reason: got %v, want something containing %q", err, tc.want)
			}
		})
	}
}

func TestParse_KeylessBundleIsIdentifiable(t *testing.T) {
	// Callers need to distinguish "this is the wrong kind of bundle" from
	// "this bundle is broken", so the sentinel is part of the contract.
	_, err := artifactsig.Parse(rewrite(t, func(m map[string]any) {
		vm := m["verificationMaterial"].(map[string]any)
		vm["certificate"] = map[string]any{"rawBytes": "AAAA"}
	}))
	if !errors.Is(err, artifactsig.ErrKeylessBundle) {
		t.Fatalf("got %v, want ErrKeylessBundle", err)
	}
}

func TestPublicKeyFromPEM_RefusesWhatIsNotAnECDSAPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshalling RSA key: %v", err)
	}
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("marshalling EC key: %v", err)
	}

	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"an RSA public key", rsaPEM, "want an ECDSA key"},
		{"not PEM at all", []byte("just some text"), "no PEM block"},
		{"a PEM block of the wrong type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ecDER}), "want PUBLIC KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := artifactsig.PublicKeyFromPEM(tc.in); err == nil {
				t.Fatal("accepted")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong reason: got %v, want something containing %q", err, tc.want)
			}
		})
	}
}

func TestVerify_RefusesWithoutAKey(t *testing.T) {
	b, artifact := loadFixture(t)
	if err := artifactsig.Verify(b, bytes.NewReader(artifact), nil); err == nil {
		t.Fatal("verified with no public key")
	}
}
