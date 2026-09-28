package pkcs11_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	p11 "github.com/miekg/pkcs11"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// The zero LoginRole is the Crypto Officer. A bare Role's zero value is
// CKU_SO, so a role field left unset anywhere would otherwise log in as
// the token's security officer.
func TestLoginRole_ZeroValueIsTheCryptoOfficerNotTheSO(t *testing.T) {
	var r pk11.LoginRole
	if r.Role() != pk11.RoleUser {
		t.Fatalf("zero LoginRole logs in as %#x, want CKU_USER", r.Role())
	}
	if r.Role() == pk11.RoleSO {
		t.Fatal("zero LoginRole is CKU_SO")
	}
	if r.Name() != pk11.RoleCryptoOfficer {
		t.Fatalf("zero LoginRole is named %q, want %q", r.Name(), pk11.RoleCryptoOfficer)
	}
	if pk11.CryptoOfficer() != r {
		t.Fatal("CryptoOfficer() is not the zero value")
	}
}

// Every adapter accepts the Crypto Officer by name and by an empty name,
// and has a row in the table: an adapter added to AdapterNames without one
// would refuse even "co".
func TestRoleByName_EveryAdapterAcceptsTheCryptoOfficer(t *testing.T) {
	for _, adapter := range pk11.AdapterNames() {
		for _, name := range []string{"", pk11.RoleCryptoOfficer} {
			r, err := pk11.RoleByName(adapter, name)
			if err != nil {
				t.Fatalf("RoleByName(%q, %q): %v", adapter, name, err)
			}
			if r.Role() != pk11.RoleUser || r.Name() != pk11.RoleCryptoOfficer {
				t.Fatalf("RoleByName(%q, %q) = %q/%#x, want co/CKU_USER", adapter, name, r.Name(), r.Role())
			}
		}
	}
}

func TestRoleByName_LunaRolesResolveToTheVendorUserTypes(t *testing.T) {
	for name, want := range map[string]pk11.Role{
		"lco": pk11.LunaRoleLimitedCryptoOfficer,
		"cu":  pk11.LunaRoleCryptoUser,
	} {
		r, err := pk11.RoleByName(pk11.AdapterLuna, name)
		if err != nil {
			t.Fatalf("RoleByName(luna, %q): %v", name, err)
		}
		if r.Role() != want || r.Name() != name {
			t.Fatalf("RoleByName(luna, %q) = %q/%#x, want %q/%#x", name, r.Name(), r.Role(), name, want)
		}
	}
}

// A vendor role given to another adapter is refused, never passed to
// C_Login as a number that module never defined, and never quietly
// replaced by the Crypto Officer.
func TestRoleByName_RefusesAnotherVendorsRoleAndUnknownNames(t *testing.T) {
	cases := []struct{ adapter, name string }{
		{pk11.AdapterSoftHSM2, "lco"},
		{pk11.AdapterProtectServer, "lco"},
		{pk11.AdapterSoftHSM2, "cu"},
		{pk11.AdapterLuna, "so"},
		{pk11.AdapterLuna, "CO"},
		{pk11.AdapterLuna, "po"},
	}
	for _, c := range cases {
		_, err := pk11.RoleByName(c.adapter, c.name)
		if !errors.Is(err, pk11.ErrUnknownRole) {
			t.Fatalf("RoleByName(%q, %q) = %v, want ErrUnknownRole", c.adapter, c.name, err)
		}
		if !strings.Contains(err.Error(), "co") {
			t.Fatalf("RoleByName(%q, %q): the refusal does not list what is accepted: %v", c.adapter, c.name, err)
		}
	}
	if _, err := pk11.RoleByName("nshield", "co"); !errors.Is(err, pk11.ErrUnknownAdapter) {
		t.Fatalf("RoleByName on an unknown adapter = %v, want ErrUnknownAdapter", err)
	}
}

// Explain adds the role's hint to CKR_USER_PIN_NOT_INITIALIZED only, the
// answer a V0 Luna partition gave to an LCO login on 2026-09-28, and
// leaves every other error, and the Crypto Officer's, as they were.
func TestLoginRole_ExplainNamesTheMissingRoleOnly(t *testing.T) {
	lco, err := pk11.RoleByName(pk11.AdapterLuna, "lco")
	if err != nil {
		t.Fatal(err)
	}
	notInit := fmt.Errorf("C_Login (anchor): %w", p11.Error(p11.CKR_USER_PIN_NOT_INITIALIZED))

	got := lco.Explain(notInit)
	if !errors.Is(got, notInit) {
		t.Fatalf("Explain lost the original error: %v", got)
	}
	if !strings.Contains(got.Error(), "V1 partition") {
		t.Fatalf("Explain(CKR_USER_PIN_NOT_INITIALIZED) for lco says nothing about V1: %v", got)
	}

	wrongPIN := fmt.Errorf("C_Login (anchor): %w", p11.Error(p11.CKR_PIN_INCORRECT))
	if got := lco.Explain(wrongPIN); got != wrongPIN {
		t.Fatalf("Explain changed an unrelated error: %v", got)
	}
	if got := pk11.CryptoOfficer().Explain(notInit); got != notInit {
		t.Fatalf("the Crypto Officer has no hint, but Explain changed the error: %v", got)
	}
	if lco.Explain(nil) != nil {
		t.Fatal("Explain(nil) is not nil")
	}
}

func TestRoleNames_CryptoOfficerFirst(t *testing.T) {
	if got := strings.Join(pk11.RoleNames(pk11.AdapterLuna), ","); got != "co,cu,lco" {
		t.Fatalf("RoleNames(luna) = %s", got)
	}
	if got := strings.Join(pk11.RoleNames(pk11.AdapterSoftHSM2), ","); got != "co" {
		t.Fatalf("RoleNames(softhsm2) = %s", got)
	}
}
