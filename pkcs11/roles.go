package pkcs11

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	p11 "github.com/miekg/pkcs11"
)

// RoleCryptoOfficer is the role name every adapter accepts: the standard
// CKU_USER, the identity every command and the service logged in as before
// the role became configurable, and still the default.
const RoleCryptoOfficer = "co"

// ErrUnknownRole reports a role name the selected adapter does not accept.
var ErrUnknownRole = errors.New("pkcs11: unknown role")

// LoginRole is the identity a caller logs into a token as, resolved from
// the name an operator typed (config.yaml's pkcs11.<adapter>.role, a
// command's -role flag). It carries the PKCS#11 user type C_Login takes and
// the name it came from, so an error can say which identity was refused.
//
// The zero value is the Crypto Officer. A bare Role's zero value is CKU_SO,
// the token's security officer, so a field that was simply left unset
// would otherwise log in as the one identity no command here should hold.
type LoginRole struct {
	name string
	role Role
	// hint, when not empty, explains the refusal CKR_USER_PIN_NOT_INITIALIZED
	// in this role's terms: the token has no initialized user of this type.
	hint string
}

// CryptoOfficer returns the Crypto Officer role, CKU_USER.
func CryptoOfficer() LoginRole { return LoginRole{} }

// Name is the role's name as an operator types it.
func (r LoginRole) Name() string {
	if r.name == "" {
		return RoleCryptoOfficer
	}
	return r.name
}

// Role is the PKCS#11 user type passed to C_Login.
func (r LoginRole) Role() Role {
	if r.name == "" {
		return RoleUser
	}
	return r.role
}

// Explain adds what the role's table entry knows about a login refusal.
// Only CKR_USER_PIN_NOT_INITIALIZED is explained: it is the answer to a
// user type the token has no initialized user for, and on its own it reads
// like a PIN problem. Any other error is returned unchanged.
func (r LoginRole) Explain(err error) error {
	var ckr p11.Error
	if err == nil || r.hint == "" || !errors.As(err, &ckr) || ckr != p11.CKR_USER_PIN_NOT_INITIALIZED {
		return err
	}
	return fmt.Errorf("%w (role %q: %s)", err, r.Name(), r.hint)
}

// NewLoginRole declares a vendor-defined login identity for a Vendor's
// Roles: the name an operator types, the user type C_Login takes, and,
// optionally, what CKR_USER_PIN_NOT_INITIALIZED means for this identity.
func NewLoginRole(name string, role Role, hint string) LoginRole {
	return LoginRole{name: name, role: role, hint: hint}
}

// lunaRoles are the vendor-defined user types the Luna adapter accepts.
// A name is accepted only for the vendor whose module defines it, so a
// Luna role given to another module is refused rather than passed to
// C_Login as a number that module never defined.
var lunaRoles = []LoginRole{
	// Measured 2026-09-28: on a V0 partition C_Login with this user
	// type answers CKR_USER_PIN_NOT_INITIALIZED, the same code a V1
	// partition gives for a role nobody initialized, so the hint names
	// both.
	{name: "lco", role: LunaRoleLimitedCryptoOfficer,
		hint: "the Limited Crypto Officer exists only on a V1 partition, so a V0 partition has none; on a V1 partition the Crypto Officer has to initialize it first (lunacm: role init -name lco)"},
	{name: "cu", role: LunaRoleCryptoUser,
		hint: "the Crypto User is not initialized on this partition (lunacm: role init -name cu, by the Partition SO)"},
}

// rolesOf is a vendor's role table: the Crypto Officer, which every
// vendor accepts, and the vendor's own.
func rolesOf(vendorRoles ...LoginRole) map[string]LoginRole {
	m := map[string]LoginRole{RoleCryptoOfficer: {}}
	for _, r := range vendorRoles {
		m[r.name] = r
	}
	return m
}

// RoleNames returns the role names adapter accepts, the Crypto Officer
// first.
func RoleNames(adapter string) []string {
	names := []string{RoleCryptoOfficer}
	var rest []string
	e, _ := lookupVendor(adapter)
	for n := range e.roles {
		if n != RoleCryptoOfficer {
			rest = append(rest, n)
		}
	}
	sort.Strings(rest)
	return append(names, rest...)
}

// RoleFlagUsage is the help text of every command's -role flag.
const RoleFlagUsage = `identity to log into the token as: "co" (Crypto Officer, the default); on -adapter luna also "lco" (Limited Crypto Officer) or "cu" (Crypto User)`

// RoleByName resolves the role name an operator gave for adapter. An empty
// name is the Crypto Officer. A name the adapter does not define is an
// error, never a fallback: a service that quietly logged in as another
// identity than its configuration says is holding authority nobody chose.
func RoleByName(adapter, name string) (LoginRole, error) {
	e, ok := lookupVendor(adapter)
	roles := e.roles
	if !ok {
		return LoginRole{}, fmt.Errorf("%w %q", ErrUnknownAdapter, adapter)
	}
	if name == "" {
		name = RoleCryptoOfficer
	}
	r, ok := roles[name]
	if !ok {
		return LoginRole{}, fmt.Errorf("%w %q for adapter %q (want %s)", ErrUnknownRole, name, adapter, strings.Join(RoleNames(adapter), ", "))
	}
	return r, nil
}
