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
// bare point with no wrapper. Try the bytes as
// a raw point first, and only attempt an ASN.1 OCTET STRING unwrap if that
// fails.
//
// That order is not arbitrary, and reversing it is a real bug this package
// shipped once: an uncompressed EC point's first byte (0x04, "uncompressed
// point indicator") is the same byte as ASN.1's OCTET STRING tag. Trying
// the ASN.1 unwrap first meant that for a bare, unwrapped point, whenever
// the point's second byte happened to numerically equal the remaining
// byte count minus 2 (probability ~1/256 for a P-256 point, since that
// byte is effectively random X-coordinate data), asn1.Unmarshal would
// spuriously succeed, slice out the wrong sub-range as if it were the
// OCTET STRING's content, and hand elliptic.Unmarshal a corrupted buffer —
// caught by TestDecodeECPoint_BareUnwrapped failing intermittently rather
// than every run, since the trigger depends on a freshly generated key's
// random bytes. Trying the raw interpretation first removes the
// ambiguity entirely: a DER-wrapped buffer is 2 bytes longer than a valid
// point, so elliptic.Unmarshal correctly rejects it on length alone and
// falls through to the unwrap step; a bare point is accepted immediately
// and the unwrap step is never reached.
func DecodeECPoint(curve elliptic.Curve, ecPoint []byte) (*ecdsa.PublicKey, error) {
	if x, y := elliptic.Unmarshal(curve, ecPoint); x != nil {
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}

	var octet []byte
	if _, err := asn1.Unmarshal(ecPoint, &octet); err == nil {
		if x, y := elliptic.Unmarshal(curve, octet); x != nil {
			return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
		}
	}

	return nil, fmt.Errorf("pkcs11: invalid EC point encoding (%d bytes)", len(ecPoint))
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
