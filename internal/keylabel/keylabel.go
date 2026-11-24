// Package keylabel is the platform's rule for the labels of the keys it
// creates. It is a policy of this CA, not of PKCS#11, so it lives beside
// the commands that apply it rather than in the PKCS#11 layer.
package keylabel

import (
	"fmt"
	"regexp"
)

// versionedPattern is the shape of every key label this platform
// creates: a lowercase purpose, then -v and a version number, for example
// ca-root-key-v1 or image-signing-key-v1. A key under a bare label cannot
// rotate without every consumer changing on the same day, and a label
// outside this alphabet is one the commands that come after the ceremony
// refuse, which would leave a CA pair on the token that no credential can
// sit beside.
var versionedPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*-v[0-9]+$`)

// ValidateVersioned reports whether label is a versioned key label. The
// ceremony, the re-issue and the signing-key commands all apply it before
// the first mutation, so a typo is an error and not a cleanup.
func ValidateVersioned(label string) error {
	if !versionedPattern.MatchString(label) {
		return fmt.Errorf("keylabel: label %q is not a versioned label (lowercase letters, digits and hyphens, ending in -v<n>, e.g. ca-root-key-v1)", label)
	}
	return nil
}
