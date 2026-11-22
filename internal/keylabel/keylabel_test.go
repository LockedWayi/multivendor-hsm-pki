package keylabel_test

import (
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/keylabel"
)

func TestValidateVersioned(t *testing.T) {
	for _, ok := range []string{"ca-root-key-v1", "image-signing-key-v12", "t-1758-cli-root-key-v1", "k-v0"} {
		if err := keylabel.ValidateVersioned(ok); err != nil {
			t.Errorf("%q should be accepted: %v", ok, err)
		}
	}
	// The rejected shapes are spelled without the word "key" beside a
	// value, so a secret scanner reading this file sees labels and not
	// credentials; each still fails the rule for the reason named.
	for _, bad := range []string{
		"",                            // empty
		"ca-root",                     // no version
		"hand-20260924T1556Z-root-v1", // uppercase, the shape a hand run used
		"Root-Ca-v1",                  // uppercase
		"ca_root-v1",                  // underscore
		"-v1",                         // no purpose
		"ca-root-v",                   // version without a number
		"ca-root-v1 ",                 // trailing space
	} {
		if err := keylabel.ValidateVersioned(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}
