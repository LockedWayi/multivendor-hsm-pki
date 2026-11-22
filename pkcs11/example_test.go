package pkcs11_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/pkcs11"
)

// A self-signed certificate whose key never leaves the token. The token
// is chosen by serial, logged into once, and signed with through a
// crypto.Signer.
func Example() {
	ctx := context.Background()
	adapter, err := pkcs11.NewAdapterByName(pkcs11.AdapterSoftHSM2, "/usr/lib/softhsm/libsofthsm2.so")
	if err != nil {
		log.Fatal(err)
	}
	defer adapter.Close()

	wss, err := adapter.Workspaces(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var ws pkcs11.Workspace
	for _, w := range wss {
		if w.Serial == os.Getenv("TOKEN_SERIAL") {
			ws = w
		}
	}

	if err := adapter.LoginToken(ctx, ws, []byte(os.Getenv("TOKEN_PIN")), pkcs11.RoleUser); err != nil {
		log.Fatal(err)
	}
	defer adapter.LogoutToken(ctx)

	signer, err := pkcs11.NewSigner(ctx, adapter, ws, pkcs11.SessionOptions{}, "example-key-v1", pkcs11.P256)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(der) > 0)
}

// A vendor this package has no adapter for, registered at start-up.
func ExampleRegisterVendor() {
	err := pkcs11.RegisterVendor(pkcs11.Vendor{
		Name: "example-hsm",
		// Measure the module with package conformance before trusting
		// this; the zero value promises nothing extra.
		Capabilities: pkcs11.Capabilities{},
		Roles: []pkcs11.LoginRole{
			pkcs11.NewLoginRole("auditor", pkcs11.Role(0x80000001), ""),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	role, err := pkcs11.RoleByName("example-hsm", "auditor")
	fmt.Println(role.Name(), err)
	// Output: auditor <nil>
}
