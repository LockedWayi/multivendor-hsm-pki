package main

import (
	"strings"
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
)

// TestNewVendorAdapter_KnowsEveryConfigAdapter: this command has its own
// switch from -adapter to a constructor, apart from the one in
// internal/config. The two must accept the same names, or a backend the
// service can run against is one the ceremony cannot be performed on.
// The module path does not exist, so every constructor fails; the
// failure must be the module's and never the name's.
func TestNewVendorAdapter_KnowsEveryConfigAdapter(t *testing.T) {
	for _, adapter := range []string{config.AdapterSoftHSM2, config.AdapterProtectServer, config.AdapterLuna} {
		t.Run(adapter, func(t *testing.T) {
			_, err := newVendorAdapter(adapter, "/nonexistent/module.so")
			if err == nil {
				t.Fatal("newVendorAdapter loaded a module that does not exist")
			}
			if strings.Contains(err.Error(), "unknown -adapter") {
				t.Fatalf("-adapter %s is a name internal/config accepts and this command does not: %v", adapter, err)
			}
		})
	}
	if _, err := newVendorAdapter("quantum-hsm", "/nonexistent/module.so"); err == nil || !strings.Contains(err.Error(), "unknown -adapter") {
		t.Fatalf("an unknown -adapter must be refused by name, got %v", err)
	}
}
