package ca_test

import (
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
)

// tlsClient and tlsServer are the built-in profiles most tests issue
// under, with a validity that fits the one-hour ceiling newTestCA sets: a
// CN-only request fits tls-client, a request with a DNS or IP name fits
// tls-server.
func tlsClient() *profile.Profile { return withValidity("tls-client", 30*time.Minute) }
func tlsServer() *profile.Profile { return withValidity("tls-server", 30*time.Minute) }

func withValidity(name string, d time.Duration) *profile.Profile {
	p := profile.Builtin()[name]
	p.Validity = d
	return p
}
