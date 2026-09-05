package ca_test

// Backend scaffolding for this package's HSM-touching tests.
//
// Every one of them runs against every backend the environment provides
//. The iteration, the skip policy, the token provisioning
// and the one-C_Initialize-per-process handling all live in
// internal/hsmtest; this file is the thin naming layer over it, because
// within the CA the two tokens are "root" and "intermediate" rather than
// "primary" and "secondary".
//
// The point of the indirection: adding nShield or Luna (Phase 7) is a new
// entry in hsmtest's registry plus an adapter, and no change at all here or
// in any test that uses this.

import (
	"testing"

	"github.com/LockedWayi/hsm-pki-platform/internal/hsmtest"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// ceremonyBackend names a hsmtest.Backend's two tokens for the CA tiers
// they hold. The field names are what this package's tests already speak.
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
		// The root goes on the secondary token: the whole point of the
		// two-token layout is that the service's token never holds it.
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

// setupSoftHSM2CeremonyBackend builds the SoftHSM2 backend specifically,
// for tests that are about SoftHSM2's own behaviour rather than about the
// abstraction — see hsmtest.SoftHSM2 for when that is legitimate.
func setupSoftHSM2CeremonyBackend(t *testing.T) *ceremonyBackend {
	t.Helper()
	return fromHSMTest(hsmtest.SoftHSM2(t))
}
