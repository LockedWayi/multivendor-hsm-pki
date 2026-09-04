package artifactsig

import (
	"bytes"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"io"
	"strings"
)

func hasPrefix(s, prefix string) bool { return strings.HasPrefix(s, prefix) }

// equalConst compares in constant time. The inputs here are public digests,
// so this is not defending a secret; it is a habit worth keeping uniform in
// a repository where the next comparison might not be public.
func equalConst(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func newStrictReader(data []byte) io.Reader { return bytes.NewReader(data) }

func firstPEMBlock(data []byte) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("artifactsig: no PEM block found")
	}
	return block, nil
}
