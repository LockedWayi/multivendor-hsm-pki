package pkcs11_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	p11 "github.com/miekg/pkcs11"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// The one operation the Limited Crypto Officer has been refused on Luna:
// logging into a V0 partition, where the role does not exist. Measured by
// hand on 2026-09-28 on two V0 partitions; kept here so the refusal, and
// the reason the platform gives for it, are checked on every run rather
// than remembered. Luna-only by nature: the fact under test is a Luna
// partition version. LUNA_V0_WORKSPACE names a V0 partition; with
// LUNA_MODULE set and it unset, the test fails, as every half-configured
// Luna setting does.
func TestLuna_TheLCOIsRefusedOnAV0PartitionAndTheErrorSaysWhy(t *testing.T) {
	modulePath := os.Getenv("LUNA_MODULE")
	if modulePath == "" {
		t.Skip("LUNA_MODULE not set: this backend is maintainer-verified, never CI-verified")
	}
	label := os.Getenv("LUNA_V0_WORKSPACE")
	if label == "" {
		t.Fatal("LUNA_MODULE is set but LUNA_V0_WORKSPACE, a V0 partition, is not")
	}
	adapter, err := pk11.NewLunaAdapter(modulePath)
	if err != nil {
		t.Fatalf("NewLunaAdapter: %v", err)
	}
	defer adapter.Close()
	ws := hsmtest.MustFindWorkspace(t, adapter, label)

	lco, err := pk11.RoleByName(pk11.AdapterLuna, "lco")
	if err != nil {
		t.Fatal(err)
	}
	// A V0 partition has no LCO whose password this could be compared
	// with, so the value is a placeholder; eight characters so a length
	// check cannot answer first.
	err = adapter.LoginToken(context.Background(), ws, []byte("00000000"), lco.Role())
	if err == nil {
		_ = adapter.LogoutToken(context.Background())
		t.Fatalf("the LCO logged into %q: either it is not a V0 partition or the finding no longer holds", label)
	}
	var ckr p11.Error
	if !errors.As(err, &ckr) || ckr != p11.CKR_USER_PIN_NOT_INITIALIZED {
		t.Fatalf("LCO login on the V0 partition = %v, want CKR_USER_PIN_NOT_INITIALIZED as measured", err)
	}
	if explained := lco.Explain(err); !strings.Contains(explained.Error(), "V1 partition") {
		t.Fatalf("the refusal is not explained: %v", explained)
	}
}
