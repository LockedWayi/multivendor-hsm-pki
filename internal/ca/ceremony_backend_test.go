package ca_test

// Backend scaffolding for this package's token-touching tests. Every one
// runs against every backend the environment provides. The iteration, the
// skip policy and the token provisioning live in internal/hsmtest; this
// file only names the two tokens "root" and "intermediate".

import (
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// ceremonyBackend names a hsmtest.Backend's two tokens for the CA tiers
// they hold.
type ceremonyBackend struct {
	name              string
	adapter           pk11.VendorAdapter
	rootWS, interWS   pk11.Workspace
	rootPIN, interPIN string
	runID             string

	backend *hsmtest.Backend
}

// label returns a run-unique object label, so a vendor whose tokens persist
// between runs does not collide with its own previous run.
func (b *ceremonyBackend) label(suffix string) string { return b.backend.Label(suffix) }

func (b *ceremonyBackend) rootKeyLabel() string  { return b.label("root-key-v1") }
func (b *ceremonyBackend) interKeyLabel() string { return b.label("inter-key-v1") }

func fromHSMTest(hb *hsmtest.Backend) *ceremonyBackend {
	return &ceremonyBackend{
		name:    hb.Name,
		adapter: hb.Adapter,
		// The root goes on the secondary token; the service's token never
		// holds it.
		rootWS:   hb.Secondary,
		interWS:  hb.Primary,
		rootPIN:  hb.SecondaryPIN,
		interPIN: hb.PrimaryPIN,
		runID:    hb.RunID,
		backend:  hb,
	}
}

// forEachCeremonyBackend runs fn against every backend the environment
// provides, each as its own subtest.
func forEachCeremonyBackend(t *testing.T, fn func(t *testing.T, b *ceremonyBackend)) {
	t.Helper()
	hsmtest.ForEach(t, func(t *testing.T, hb *hsmtest.Backend) {
		fn(t, fromHSMTest(hb))
	})
}

// setupSoftHSM2CeremonyBackend builds the SoftHSM2 backend, for tests
// about SoftHSM2's own behaviour.
func setupSoftHSM2CeremonyBackend(t *testing.T) *ceremonyBackend {
	t.Helper()
	return fromHSMTest(hsmtest.SoftHSM2(t))
}
