package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
)

// DecodeECPoint decodes a PKCS#11 CKA_EC_POINT attribute value into a
// crypto/ecdsa public key on curve.
//
// The PKCS#11 spec says CKA_EC_POINT is a DER-encoded OCTET STRING wrapping
// the uncompressed point; some tokens return exactly that, others return the
// bare point with no wrapper (docs/pkcs11-vendor-notes.md). This tries an
// ASN.1 OCTET STRING unwrap first — using encoding/asn1 rather than
// hand-decoding the DER length byte, so both short-form and long-form DER
// lengths are handled correctly (a P-521 point is 133 bytes, which already
// needs a long-form length) — and falls back to treating the input as the
// raw point if that unwrap fails.
func DecodeECPoint(curve elliptic.Curve, ecPoint []byte) (*ecdsa.PublicKey, error) {
	raw := ecPoint
	var octet []byte
	if _, err := asn1.Unmarshal(ecPoint, &octet); err == nil {
		raw = octet
	}

	x, y := elliptic.Unmarshal(curve, raw)
	if x == nil {
		return nil, fmt.Errorf("pkcs11: invalid EC point encoding (%d bytes)", len(ecPoint))
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// Curve returns the elliptic.Curve for c, or nil for an ECCurve this
// package does not implement.
func (c ECCurve) Curve() elliptic.Curve {
	switch c {
	case P256:
		return elliptic.P256()
	case P384:
		return elliptic.P384()
	case P521:
		return elliptic.P521()
	default:
		return nil
	}
}
