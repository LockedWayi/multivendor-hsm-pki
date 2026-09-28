package main

import (
	"context"
	"flag"
	"fmt"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// addRoleFlag registers -role, the identity every token this command
// touches is logged into as. One flag, not one per token: the operator
// names one identity, and a token that has no such user refuses the login
// with an explanation before anything is created.
func addRoleFlag(fs *flag.FlagSet) *string {
	return fs.String("role", pk11.RoleCryptoOfficer, pk11.RoleFlagUsage)
}

// loginAs logs adapter into ws as role. pin is zeroed by LoginToken. A
// refusal names the role and carries what the role table knows about it,
// so an LCO login on a partition with no LCO says so instead of reading
// like a wrong PIN.
func loginAs(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, pin []byte, role pk11.LoginRole) error {
	if err := adapter.LoginToken(ctx, ws, pin, role.Role()); err != nil {
		return fmt.Errorf("logging into %q as %q: %w", ws.Label, role.Name(), role.Explain(err))
	}
	return nil
}
