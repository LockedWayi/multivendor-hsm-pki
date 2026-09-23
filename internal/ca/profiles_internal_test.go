package ca

import (
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
)

// clientFor is the built-in tls-client profile granting d, for tests
// that build a CA with a ceiling of their own.
func clientFor(d time.Duration) *profile.Profile {
	p := profile.Builtin()["tls-client"]
	p.Validity = d
	return p
}

func tlsClient() *profile.Profile { return clientFor(30 * time.Minute) }
