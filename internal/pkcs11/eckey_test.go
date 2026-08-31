package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"testing"
)

func TestDecodeECPoint_DERWrappedShortForm(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	point := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y) // 65 bytes: short-form DER length
	wrapped, err := asn1.Marshal(point)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}

	got, err := DecodeECPoint(elliptic.P256(), wrapped)
	if err != nil {
		t.Fatalf("DecodeECPoint: %v", err)
	}
	if got.X.Cmp(priv.X) != 0 || got.Y.Cmp(priv.Y) != 0 {
		t.Fatal("decoded point does not match the original public key")
	}
}

func TestDecodeECPoint_DERWrappedLongForm(t *testing.T) {
	// A P-521 point is 133 bytes — long enough that its OCTET STRING
	// wrapper needs a long-form DER length (short-form tops out at 127).
	// This is the case the earlier hand-rolled "0x04 <len> <point>" decode
	// (conformance_test.go's original helper) would have gotten wrong.
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	point := elliptic.Marshal(elliptic.P521(), priv.X, priv.Y)
	if len(point) <= 127 {
		t.Fatalf("test assumption violated: P-521 point is only %d bytes", len(point))
	}
	wrapped, err := asn1.Marshal(point)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}

	got, err := DecodeECPoint(elliptic.P521(), wrapped)
	if err != nil {
		t.Fatalf("DecodeECPoint: %v", err)
	}
	if got.X.Cmp(priv.X) != 0 || got.Y.Cmp(priv.Y) != 0 {
		t.Fatal("decoded point does not match the original public key")
	}
}

func TestDecodeECPoint_BareUnwrapped(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	point := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)

	got, err := DecodeECPoint(elliptic.P256(), point)
	if err != nil {
		t.Fatalf("DecodeECPoint: %v", err)
	}
	if got.X.Cmp(priv.X) != 0 || got.Y.Cmp(priv.Y) != 0 {
		t.Fatal("decoded point does not match the original public key")
	}
}

// TestDecodeECPoint_BareUnwrapped_ASN1TagCollision deterministically
// reproduces the exact condition that made TestDecodeECPoint_BareUnwrapped
// intermittently fail before DecodeECPoint tried the raw interpretation
// first: a bare, unwrapped point whose second byte happens to equal 0x3F
// (63) — the DER short-form length of the remaining 63 bytes — which
// otherwise makes it possible to misparse as an ASN.1-wrapped OCTET
// STRING. Rather than rely on a ~1/256 chance per random key, generate
// keys until one lands on that exact byte value, capping the search well
// above the expected ~256 draws so a regression here fails loudly instead
// of flaking.
func TestDecodeECPoint_BareUnwrapped_ASN1TagCollision(t *testing.T) {
	const collidingSecondByte = 0x3F
	var point []byte
	for i := 0; i < 100_000; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		candidate := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)
		if candidate[1] == collidingSecondByte {
			point = candidate
			break
		}
	}
	if point == nil {
		t.Fatal("did not find a colliding point within 100,000 draws — something about the collision probability assumption is wrong")
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), point)
	if x == nil {
		t.Fatal("test bug: generated point does not itself unmarshal")
	}

	got, err := DecodeECPoint(elliptic.P256(), point)
	if err != nil {
		t.Fatalf("DecodeECPoint on a colliding bare point: %v", err)
	}
	if got.X.Cmp(x) != 0 || got.Y.Cmp(y) != 0 {
		t.Fatal("decoded point does not match the original, despite the ASN.1 tag collision")
	}
}

func TestDecodeECPoint_InvalidFails(t *testing.T) {
	if _, err := DecodeECPoint(elliptic.P256(), []byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("DecodeECPoint on garbage input succeeded, want an error")
	}
}

func TestECCurve_Curve(t *testing.T) {
	cases := []struct {
		c    ECCurve
		want elliptic.Curve
	}{
		{P256, elliptic.P256()},
		{P384, elliptic.P384()},
		{P521, elliptic.P521()},
	}
	for _, tc := range cases {
		if got := tc.c.Curve(); got != tc.want {
			t.Fatalf("ECCurve(%d).Curve() = %v, want %v", tc.c, got, tc.want)
		}
	}
	if got := ECCurve(99).Curve(); got != nil {
		t.Fatalf("ECCurve(99).Curve() = %v, want nil", got)
	}
}
