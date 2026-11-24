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
		if !strings.Contains(err.Error(), name) || !strings.Contains(pk11.AdapterFlagUsage(), name) {
			t.Fatalf("the refusal and the flag usage must name every accepted adapter; missing %q in %q / %q", name, err, pk11.AdapterFlagUsage())
		}
	}
}

// A registered vendor is reachable through every name-driven entry point:
// AdapterNames, the flag usage, NewAdapterByName and RoleByName, with its
// own roles accepted and no other vendor's.
func TestRegisterVendor_ReachableByName(t *testing.T) {
	const name = "test-registered-vendor"
	err := pk11.RegisterVendor(pk11.Vendor{
		Name:  name,
		Roles: []pk11.LoginRole{pk11.NewLoginRole("auditor", pk11.Role(0x80000010), "")},
	})
	if err != nil {
		t.Fatalf("RegisterVendor: %v", err)
	}
	found := false
	for _, n := range pk11.AdapterNames() {
		found = found || n == name
	}
	if !found || !strings.Contains(pk11.AdapterFlagUsage(), name) {
		t.Fatalf("%q missing from AdapterNames %v or the flag usage %q", name, pk11.AdapterNames(), pk11.AdapterFlagUsage())
	}
	if _, err := pk11.NewAdapterByName(name, "/nonexistent/module.so"); err == nil || errors.Is(err, pk11.ErrUnknownAdapter) {
		t.Fatalf("NewAdapterByName must try the module and fail on it, got %v", err)
	}
	r, err := pk11.RoleByName(name, "auditor")
	if err != nil || r.Role() != pk11.Role(0x80000010) || r.Name() != "auditor" {
		t.Fatalf("RoleByName(auditor) = %v, %v", r, err)
	}
	if _, err := pk11.RoleByName(name, "lco"); !errors.Is(err, pk11.ErrUnknownRole) {
		t.Fatalf("another vendor's role must be refused, got %v", err)
	}
	if _, err := pk11.RoleByName(name, ""); err != nil {
		t.Fatalf("every vendor accepts the Crypto Officer: %v", err)
	}
}

func TestRegisterVendor_Refusals(t *testing.T) {
	for _, tc := range []struct {
		what string
		v    pk11.Vendor
	}{
		{"empty name", pk11.Vendor{}},
		{"uppercase name", pk11.Vendor{Name: "Vendor"}},
		{"name with a space", pk11.Vendor{Name: "my vendor"}},
		{"built-in name", pk11.Vendor{Name: pk11.AdapterLuna}},
		{"unnamed role", pk11.Vendor{Name: "refused-a", Roles: []pk11.LoginRole{pk11.NewLoginRole("", 1, "")}}},
		{"redefines the Crypto Officer", pk11.Vendor{Name: "refused-b", Roles: []pk11.LoginRole{pk11.NewLoginRole(pk11.RoleCryptoOfficer, pk11.RoleSO, "")}}},
		{"role named twice", pk11.Vendor{Name: "refused-c", Roles: []pk11.LoginRole{pk11.NewLoginRole("x", 1, ""), pk11.NewLoginRole("x", 2, "")}}},
	} {
		if err := pk11.RegisterVendor(tc.v); !errors.Is(err, pk11.ErrVendorRegistration) {
			t.Errorf("%s: want ErrVendorRegistration, got %v", tc.what, err)
		}
	}
	for _, n := range pk11.AdapterNames() {
		if strings.HasPrefix(n, "refused-") {
			t.Fatalf("a refused vendor was registered: %q", n)
		}
	}
}
