package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
)

// DecodeECPoint decodes a CKA_EC_POINT value into a public key on curve.
// PKCS#11 defines CKA_EC_POINT as a DER OCTET STRING wrapping the
// uncompressed point; some tokens return the bare point. The bare form is
// tried first. An uncompressed point starts with 0x04, which is also the
// OCTET STRING tag, so trying the ASN.1 unwrap first accepted a bare point
// as DER about once in 256 keys and handed elliptic.Unmarshal a corrupted
// buffer. A DER-wrapped buffer is two bytes longer than a point, so the
// raw attempt rejects it on length and falls through.
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
