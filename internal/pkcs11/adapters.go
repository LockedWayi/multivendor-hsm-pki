package pkcs11

import (
	"errors"
	"fmt"
	"regexp"
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

// versionedLabelPattern is the shape of every key label this platform
// creates: a lowercase purpose, then -v and a version number, for example
// ca-root-key-v1 or image-signing-key-v1. A key under a bare label cannot
// rotate without every consumer changing on the same day, and a label
// outside this alphabet is one the commands that come after the ceremony
// refuse, which would leave a CA pair on the token that no credential can
// sit beside.
var versionedLabelPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*-v[0-9]+$`)

// ValidateVersionedLabel reports whether label is a versioned key label.
// The ceremony, the re-issue and the signing-key commands all apply it
// before the first mutation, so a typo is an error and not a cleanup.
func ValidateVersionedLabel(label string) error {
	if !versionedLabelPattern.MatchString(label) {
		return fmt.Errorf("pkcs11: label %q is not a versioned label (lowercase letters, digits and hyphens, ending in -v<n>, e.g. ca-root-key-v1)", label)
	}
	return nil
}
