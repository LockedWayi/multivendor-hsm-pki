package artifactsig_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
// bundle format were wrong.
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
	// image key must not verify an artifact signature.
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
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(b.Signature, &parsed); err != nil {
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
				delete(vm, "publicKey")
				vm["certificate"] = map[string]any{"rawBytes": "AAAA"}
			},
			want: "keyless bundle",
		},
		{
			// The older keyless shape. Checking only `certificate` would
			// have let this through as keyed material.
			name: "keyless bundle carrying an x509 certificate chain",
			mutate: func(m map[string]any) {
				vm := m["verificationMaterial"].(map[string]any)
				delete(vm, "publicKey")
				vm["x509CertificateChain"] = map[string]any{"certificates": []any{}}
			},
			want: "keyless bundle",
		},
		{
			name: "no verification material at all",
			mutate: func(m map[string]any) {
				m["verificationMaterial"] = map[string]any{}
			},
			want: "no verification material",
		},
		{
			name: "no content at all",
			mutate: func(m map[string]any) {
				delete(m, "messageSignature")
			},
			want: "signs nothing",
		},
		{
			name: "a message digest that is not 32 bytes",
			mutate: func(m map[string]any) {
				md := m["messageSignature"].(map[string]any)["messageDigest"].(map[string]any)
				md["digest"] = "AAAA"
			},
			want: "not the 32",
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
			// The arm is present but empty, which is a different failure
			// from the arm being absent and must read as one.
			name: "public key material carrying no hint",
			mutate: func(m map[string]any) {
				m["verificationMaterial"].(map[string]any)["publicKey"] = map[string]any{}
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

// TestParse_RefusesTwoArmsOfOneOneof covers the gap this package shipped
// with: it checked for `certificate` and nothing else, so a bundle carrying
// BOTH a published key and certificate material, or BOTH a blob signature
// and a DSSE envelope, was accepted and one arm silently discarded.
// Measured open before the fix.
//
// sigstore_bundle.proto defines both as `oneof`, and that is the point: two
// arms are not an extra field, they are two contradictory claims about what
// authenticates the signature or about what it covers. Choosing either is
// choosing for a sender who said two things.
func TestParse_RefusesTwoArmsOfOneOneof(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m map[string]any)
		want   string
	}{
		{
			name: "keyed and certificate-chain material at once",
			mutate: func(m map[string]any) {
				vm := m["verificationMaterial"].(map[string]any)
				vm["x509CertificateChain"] = map[string]any{"certificates": []any{}}
			},
			want: "exactly one",
		},
		{
			name: "keyed and single-certificate material at once",
			mutate: func(m map[string]any) {
				vm := m["verificationMaterial"].(map[string]any)
				vm["certificate"] = map[string]any{"rawBytes": "AAAA"}
			},
			want: "exactly one",
		},
		{
			name: "a blob signature and a DSSE envelope at once",
			mutate: func(m map[string]any) {
				m["dsseEnvelope"] = map[string]any{"payload": "AAAA", "payloadType": "application/vnd.in-toto+json"}
			},
			want: "exactly one",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := artifactsig.Parse(rewrite(t, tc.mutate))
			if err == nil {
				t.Fatal("accepted a bundle making two contradictory claims")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong reason: got %v", err)
			}
		})
	}
}

// TestParse_AcceptsABundleCarryingFieldsThisPackageDoesNotRead is the other
// half of the same decision, and the reason DisallowUnknownFields was not
// the fix. A real Sigstore bundle carries tlogEntries and
// timestampVerificationData; measured, Go's strict decoding rejects cosign's
// own release bundles over exactly that. Strictness has to fall on the
// fields that change meaning, not on every field.
func TestParse_AcceptsABundleCarryingFieldsThisPackageDoesNotRead(t *testing.T) {
	raw := rewrite(t, func(m map[string]any) {
		m["verificationMaterial"].(map[string]any)["tlogEntries"] = []any{
			map[string]any{"logIndex": "2352228362"},
		}
		m["verificationMaterial"].(map[string]any)["timestampVerificationData"] = map[string]any{}
	})
	b, err := artifactsig.Parse(raw)
	if err != nil {
		t.Fatalf("a valid bundle with a transparency log entry was rejected: %v", err)
	}
	_, artifact := loadFixture(t)
	if err := artifactsig.Verify(b, bytes.NewReader(artifact), loadKey(t, publishedKey)); err != nil {
		t.Fatalf("and it no longer verifies: %v", err)
	}
}

func TestParse_KeylessBundleIsIdentifiable(t *testing.T) {
	// Callers need to distinguish "this is the wrong kind of bundle" from
	// "this bundle is broken", so the sentinel is part of the contract.
	_, err := artifactsig.Parse(rewrite(t, func(m map[string]any) {
		vm := m["verificationMaterial"].(map[string]any)
		delete(vm, "publicKey")
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

// TestParse_AcceptsAForeignBundleProducedByAnotherToolchain is the
// tolerance half of the oneof decision, proven against a bundle this
// repository did not make: cosign's own v3.1.3 release signature, as
// published by the Sigstore project. It carries tlogEntries,
// inclusionProof, checkpoint and rfc3161Timestamps — none of which this
// package reads — and it is the artifact whose verification bootstraps
// ci/cosign.sh.
//
// It is here because the synthetic version of this test supplies its own
// answer: a bundle written by the test to carry fields
// the test chose proves only that the test agrees with itself. This one was
// produced by a different toolchain, on a different day, for a different
// artifact, and it is what a strict-by-default parser would have rejected.
func TestParse_AcceptsAForeignBundleProducedByAnotherToolchain(t *testing.T) {
	raw, err := os.ReadFile("testdata/foreign-cosign-release.sigstore.json")
	if err != nil {
		t.Fatalf("reading the foreign bundle: %v", err)
	}
	b, err := artifactsig.Parse(raw)
	if err != nil {
		t.Fatalf("a real Sigstore bundle was rejected: %v", err)
	}
	// It names the Sigstore release key this repository pins, which is the
	// same identity check ci/cosign.sh makes before trusting the download.
	anchor, err := os.ReadFile("../../ci/sigstore-release-cosign.pub")
	if err != nil {
		t.Fatalf("reading the pinned release key: %v", err)
	}
	pub, err := artifactsig.PublicKeyFromPEM(anchor)
	if err != nil {
		t.Fatalf("parsing the pinned release key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("encoding the pinned release key: %v", err)
	}
	sum := sha256.Sum256(spki)
	if want := base64.StdEncoding.EncodeToString(sum[:]); b.KeyHint != want {
		t.Fatalf("the foreign bundle names key %s, the pinned release key is %s", b.KeyHint, want)
	}
	if len(b.Digest) != sha256.Size || len(b.Signature) == 0 {
		t.Fatalf("parsed a bundle with digest %d bytes and signature %d bytes", len(b.Digest), len(b.Signature))
	}
}
