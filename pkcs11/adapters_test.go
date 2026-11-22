package pkcs11_test

import (
	"errors"
	"strings"
	"testing"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/pkcs11"
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
