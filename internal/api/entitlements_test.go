package api_test

import (
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/entitlement"
)

// entitled binds each identity to every client profile and any name, the
// arrangement the tests that are not about policy run under. The
// policy tests build their own narrower maps.
func entitled(ids ...string) entitlement.Map {
	specs := make(map[string]entitlement.Spec, len(ids))
	for _, id := range ids {
		specs[id] = entitlement.Spec{
			Profiles: []string{"tls-server", "tls-client", "code-signing"},
			Names:    []string{"cn:*", "dns:*", "ip:*", "uri:*", "email:*"},
		}
	}
	m, err := entitlement.Parse(specs)
	if err != nil {
		panic(err)
	}
	return m
}

// mustEntitlements parses a mapping or fails the test.
func mustEntitlements(t *testing.T, specs map[string]entitlement.Spec) entitlement.Map {
	t.Helper()
	m, err := entitlement.Parse(specs)
	if err != nil {
		t.Fatalf("entitlement.Parse: %v", err)
	}
	return m
}
