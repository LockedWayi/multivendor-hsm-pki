package pkcs11

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Adapter names, as config.yaml's pkcs11.adapter, the -adapter flag of
// every command and internal/hsmtest's registry spell them. Every switch
// on an adapter name goes through NewAdapterByName, so a vendor in the
// registry is reachable from every entry point at once.
const (
	AdapterSoftHSM2      = "softhsm2"
	AdapterProtectServer = "protectserver"
	AdapterLuna          = "luna"
)

// Vendor declares a PKCS#11 module family that this package has no
// adapter for, so that a program can drive it through the shared
// implementation without a change here. The built-in adapters are
// registered the same way.
//
// A vendor is data, not code: what its module was measured to do
// (Capabilities) and the vendor-defined login identities it accepts
// (Roles). Run the conformance suite (package conformance) against the
// module before trusting the declaration; a field the module does not
// match is a failing subtest there.
type Vendor struct {
	// Name is what an operator selects the vendor by. Lowercase, unique.
	Name string
	// Capabilities is the vendor's measured declaration. The zero value
	// is the most restrictive one and is a safe start for a module not
	// measured yet.
	Capabilities Capabilities
	// Roles lists the vendor-defined login identities beyond the Crypto
	// Officer, which every vendor accepts and which may not be listed
	// here. See NewLoginRole.
	Roles []LoginRole
}

// vendorEntry is one row of the registry: how to construct the adapter
// and which role names it accepts.
type vendorEntry struct {
	name  string
	open  func(modulePath string) (VendorAdapter, error)
	roles map[string]LoginRole
}

var (
	registryMu sync.RWMutex
	// registry is in the order the vendors joined, which is the order
	// AdapterNames reports.
	registry = []vendorEntry{
		{AdapterSoftHSM2, opener(NewSoftHSM2Adapter), rolesOf()},
		{AdapterProtectServer, opener(NewProtectServerAdapter), rolesOf()},
		{AdapterLuna, opener(NewLunaAdapter), rolesOf(lunaRoles...)},
	}
)

// opener adapts a built-in constructor to the registry's shape. A failed
// constructor's nil pointer is returned as a nil interface, never as a
// non-nil VendorAdapter holding nil.
func opener[A VendorAdapter](newA func(string) (A, error)) func(string) (VendorAdapter, error) {
	return func(modulePath string) (VendorAdapter, error) {
		a, err := newA(modulePath)
		if err != nil {
			return nil, err
		}
		return a, nil
	}
}

// ErrVendorRegistration reports a Vendor that RegisterVendor refused.
var ErrVendorRegistration = errors.New("pkcs11: vendor not registered")

// RegisterVendor adds v to the names NewAdapterByName, AdapterNames and
// RoleByName accept. It refuses an empty or already registered name, a
// role without a name, a role named twice, and a role that redefines the
// Crypto Officer. Call it before the first adapter is opened, typically
// from an init function.
func RegisterVendor(v Vendor) error {
	if v.Name == "" || v.Name != strings.ToLower(v.Name) || strings.ContainsAny(v.Name, " \t\n") {
		return fmt.Errorf("%w: name %q must be lowercase and non-empty, without spaces", ErrVendorRegistration, v.Name)
	}
	for _, r := range v.Roles {
		if r.name == "" || r.name == RoleCryptoOfficer {
			return fmt.Errorf("%w: vendor %q: a role must be named, and %q is every vendor's already", ErrVendorRegistration, v.Name, RoleCryptoOfficer)
		}
	}
	roles := rolesOf(v.Roles...)
	if len(roles) != len(v.Roles)+1 {
		return fmt.Errorf("%w: vendor %q names a role twice", ErrVendorRegistration, v.Name)
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	for _, e := range registry {
		if e.name == v.Name {
			return fmt.Errorf("%w: %q is already registered", ErrVendorRegistration, v.Name)
		}
	}
	caps := v.Capabilities
	registry = append(registry, vendorEntry{
		name:  v.Name,
		open:  func(p string) (VendorAdapter, error) { return NewAdapter(p, caps) },
		roles: roles,
	})
	return nil
}

// NewAdapter loads and initializes the module at modulePath through the
// shared implementation, driven as caps declares. It is what every
// built-in adapter wraps, for a vendor this package has no type for.
func NewAdapter(modulePath string, caps Capabilities) (VendorAdapter, error) {
	return newPKCS11Adapter(modulePath, caps)
}

func lookupVendor(name string) (vendorEntry, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	for _, e := range registry {
		if e.name == name {
			return e, true
		}
	}
	return vendorEntry{}, false
}

// AdapterNames returns every name NewAdapterByName accepts, in the order
// the backends joined.
func AdapterNames() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, len(registry))
	for i, e := range registry {
		names[i] = e.name
	}
	return names
}

// AdapterFlagUsage is the help text of every command's -adapter flag,
// built from AdapterNames so the flags cannot fall behind the list.
func AdapterFlagUsage() string {
	return "vendor adapter: " + quotedNames()
}

func quotedNames() string {
	names := AdapterNames()
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	if len(quoted) == 1 {
		return quoted[0]
	}
	return strings.Join(quoted[:len(quoted)-1], ", ") + " or " + quoted[len(quoted)-1]
}

// ErrUnknownAdapter reports an adapter name outside AdapterNames.
var ErrUnknownAdapter = errors.New("pkcs11: unknown adapter")

// NewAdapterByName loads and initializes the module at modulePath through
// the adapter that name selects. It opens no session and does not log in.
func NewAdapterByName(name, modulePath string) (VendorAdapter, error) {
	e, ok := lookupVendor(name)
	if !ok {
		return nil, fmt.Errorf("%w %q (want %s)", ErrUnknownAdapter, name, quotedNames())
	}
	return e.open(modulePath)
}
