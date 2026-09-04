package artifactsig_test

import "crypto/sha256"

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
