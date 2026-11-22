package pkcs11

import (
	"errors"
	"fmt"
	"strings"
)

// Adapter names, as config.yaml's pkcs11.adapter, the -adapter flag of
// every command and internal/hsmtest's registry spell them. This is the
// one list; every switch on an adapter name goes through NewAdapterByName
// so a vendor added here is reachable from every entry point at once.
const (
	AdapterSoftHSM2      = "softhsm2"
	AdapterProtectServer = "protectserver"
	AdapterLuna          = "luna"
)

// AdapterNames returns every name NewAdapterByName accepts, in the order
// the backends joined.
func AdapterNames() []string {
	return []string{AdapterSoftHSM2, AdapterProtectServer, AdapterLuna}
}

// AdapterFlagUsage is the help text of every command's -adapter flag,
// built from AdapterNames so the flags cannot fall behind the list.
var AdapterFlagUsage = func() string {
	names := AdapterNames()
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return "vendor adapter: " + strings.Join(quoted[:len(quoted)-1], ", ") + " or " + quoted[len(quoted)-1]
}()

// ErrUnknownAdapter reports an adapter name outside AdapterNames.
var ErrUnknownAdapter = errors.New("pkcs11: unknown adapter")

// NewAdapterByName loads and initializes the module at modulePath through
// the adapter that name selects. It opens no session and does not log in.
func NewAdapterByName(name, modulePath string) (VendorAdapter, error) {
	switch name {
	case AdapterSoftHSM2:
		return NewSoftHSM2Adapter(modulePath)
	case AdapterProtectServer:
		return NewProtectServerAdapter(modulePath)
	case AdapterLuna:
		return NewLunaAdapter(modulePath)
	default:
		return nil, fmt.Errorf("%w %q (want %s)", ErrUnknownAdapter, name, strings.TrimPrefix(AdapterFlagUsage, "vendor adapter: "))
	}
}
