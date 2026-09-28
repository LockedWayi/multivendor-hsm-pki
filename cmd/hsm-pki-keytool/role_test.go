package main

import (
	"errors"
	"testing"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// Every command that logs into a token takes -role, and refuses a role the
// adapter does not define before it checks anything else or loads a
// module: a Luna role on another adapter, or a name nobody defined.
// Nothing here reaches a token, so no backend is needed.
func TestEveryCommand_RefusesARoleTheAdapterDoesNotDefine(t *testing.T) {
	commands := []string{
		"ceremony", "reissue-intermediate", "provision-signing-key", "retire-signing-key",
		"generate-inventory", "provision-tls-identity", "issue-client-cert", "provision-ocsp-key",
	}
	for _, cmd := range commands {
		for _, c := range []struct{ adapter, role string }{
			{pk11.AdapterSoftHSM2, "lco"},
			{pk11.AdapterProtectServer, "cu"},
			{pk11.AdapterLuna, "so"},
		} {
			err := run([]string{cmd, "-adapter", c.adapter, "-role", c.role})
			if !errors.Is(err, pk11.ErrUnknownRole) {
				t.Errorf("%s -adapter %s -role %s = %v, want ErrUnknownRole before anything else", cmd, c.adapter, c.role, err)
			}
		}
	}
}
