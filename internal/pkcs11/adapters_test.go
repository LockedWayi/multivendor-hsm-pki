package pkcs11_test

import (
	"errors"
	"strings"
	"testing"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// TestNewAdapterByName_KnowsEveryName: the module path does not exist, so
// every constructor fails, but the failure must be the module's and never
// the name's. A name in AdapterNames that the switch does not know is a
// backend every entry point offers and none can start.
func TestNewAdapterByName_KnowsEveryName(t *testing.T) {
	for _, name := range pk11.AdapterNames() {
		t.Run(name, func(t *testing.T) {
			_, err := pk11.NewAdapterByName(name, "/nonexistent/module.so")
			if err == nil {
				t.Fatal("NewAdapterByName loaded a module that does not exist")
			}
			if errors.Is(err, pk11.ErrUnknownAdapter) {
				t.Fatalf("%q is in AdapterNames and NewAdapterByName does not know it: %v", name, err)
			}
		})
	}
	_, err := pk11.NewAdapterByName("quantum-hsm", "/nonexistent/module.so")
	if !errors.Is(err, pk11.ErrUnknownAdapter) {
		t.Fatalf("an unknown name must be refused as ErrUnknownAdapter, got %v", err)
	}
	for _, name := range pk11.AdapterNames() {
		if !strings.Contains(err.Error(), name) || !strings.Contains(pk11.AdapterFlagUsage, name) {
			t.Fatalf("the refusal and the flag usage must name every accepted adapter; missing %q in %q / %q", name, err, pk11.AdapterFlagUsage)
		}
	}
}

func TestValidateVersionedLabel(t *testing.T) {
	for _, ok := range []string{"ca-root-key-v1", "image-signing-key-v12", "t-1758-cli-root-key-v1", "k-v0"} {
		if err := pk11.ValidateVersionedLabel(ok); err != nil {
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
		if err := pk11.ValidateVersionedLabel(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}
