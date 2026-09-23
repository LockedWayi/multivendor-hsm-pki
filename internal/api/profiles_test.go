package api_test

import (
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
)

// tlsClient and tlsServer are the built-in profiles the tests issue
// under, with a validity that fits the test CA's one-hour ceiling: client
// credentials under the first, the listener's identity under the second.
func tlsClient() *profile.Profile { return withValidity("tls-client", 30*time.Minute) }
func tlsServer() *profile.Profile { return withValidity("tls-server", 30*time.Minute) }

func withValidity(name string, d time.Duration) *profile.Profile {
	p := profile.Builtin()[name]
	p.Validity = d
	return p
}

// testProfiles is the set the test servers issue under: the built-ins,
// each granting thirty minutes so every one fits the ceiling.
func testProfiles() profile.Set {
	set := profile.Builtin()
	for _, p := range set {
		p.Validity = 30 * time.Minute
	}
	return set
}
