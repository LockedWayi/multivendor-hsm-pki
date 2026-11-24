# pkcs11: one interface over several HSM vendors

```sh
go get github.com/LockedWayi/multivendor-hsm-pki/pkcs11
```

A Go layer over PKCS#11 that drives three vendors' modules through one
interface, `VendorAdapter`, with no branch on a vendor's name. Where
conforming modules behave differently, the difference is a field of
`Capabilities`: a declaration the adapter makes and a conformance suite
measures. The Certificate Authority in this repository is built on it.

**Status: v0.** The API may change in a minor release until v1. The
package lives in the CA's module for now. It moves to a module of its own
once the API settles. Requires cgo and Linux, the only platform measured.

## Backends

| Vendor | Adapter name | Verified against | How |
|---|---|---|---|
| SoftHSM2 | `softhsm2` | SoftHSM2 2.6.1 | **CI**, every push |
| Thales ProtectServer | `protectserver` | ProtectToolkit-C 7.3.3 software emulation (`libctsw.so`) | Maintainer, not an appliance |
| Thales Luna Network HSM 7 | `luna` | Luna HSM Client 10.9.4, firmware 7.8.7, password-authenticated partitions | Maintainer, hardware |
| Entrust nShield | none | not run | No hardware available. Planned |

"Maintainer" means the conformance suite passed in the maintainer's own
environment. Nothing in that column is a CI result. What each vendor was
measured to do, and when, is in the comment on its `Capabilities` value
(`softhsm2.go`, `protectserver.go`, `luna.go`) and in
[docs/test-matrix.md](../docs/test-matrix.md).

## Signing with a key on the token

```go
adapter, err := pkcs11.NewAdapterByName("luna", "/usr/safenet/lunaclient/libs/64/libCryptoki2.so")
if err != nil { ... }
defer adapter.Close()

// Identify the token by its serial, never by its label: CKA_LABEL is a
// description and PKCS#11 does not make it unique.
wss, _ := adapter.Workspaces(ctx)
ws := pick(wss, serial)

// Authenticate once. PKCS#11 authenticates a token for the whole
// application, so every session opened afterwards can use private keys.
// The PIN is zeroed in place.
if err := adapter.LoginToken(ctx, ws, pin, pkcs11.RoleUser); err != nil { ... }

signer, err := pkcs11.NewSigner(ctx, adapter, ws, pkcs11.SessionOptions{}, "my-key-v1", pkcs11.P256)
// signer is a crypto.Signer: x509.CreateCertificate, tls.Certificate, ...
```

`example_test.go` has this as a compiled example.

## What the layer guarantees

- **Keys are created non-extractable in plaintext.** `GenerateKeyPair`,
  `GenerateSecretKey` and `Unwrap` set `CKA_SENSITIVE` true whatever the
  request says. There is no field to turn it off.
- **Ambiguity fails closed.** `FindKeyByLabel` refuses a label that matches
  more than one object (`ErrAmbiguousLabel`), and `DestroyObject` takes a
  handle, never a label.
- **Sessions expire.** Every session carries an idle timeout and a maximum
  lifetime (15 minutes and 8 hours by default). Past either, every call
  fails with `ErrSessionExpired`, and a background sweep closes it.
- **PINs live outside the Go heap** while this code holds them
  (`SecurePIN`). One copy is not under this package's control; see
  [Known limits](#known-limits).
- **A module that must be driven from one OS thread is.** A module that
  declares `SerializeOnOneThread` has every call funnelled to one pinned
  thread.

## Adding a vendor

A vendor is data, not code. Every built-in adapter wraps the same
implementation with no overrides, and a vendor this package does not know
can be added from outside it:

```go
func init() {
	err := pkcs11.RegisterVendor(pkcs11.Vendor{
		Name:         "myhsm",
		Capabilities: pkcs11.Capabilities{}, // restrictive except SerializeOnOneThread; see Capabilities
		Roles: []pkcs11.LoginRole{
			pkcs11.NewLoginRole("auditor", pkcs11.Role(0x80000001), "the auditor role is not initialized on this token"),
		},
	})
	if err != nil { panic(err) }
}
```

`myhsm` is then accepted wherever an adapter name is, and `auditor` by
`RoleByName("myhsm", ...)`. Then measure the module:

```go
func TestMyHSM(t *testing.T) {
	open := func() (pkcs11.VendorAdapter, error) {
		return pkcs11.NewAdapterByName("myhsm", os.Getenv("MYHSM_MODULE"))
	}
	a, err := open()
	if err != nil { t.Fatal(err) }
	conformance.Run(t, conformance.Target{
		Name: "MyHSM", Adapter: a, Workspace: ws,
		PIN: pin, WrongPIN: []byte("00000000"), Reopen: open,
	})
}
```

The suite (`pkcs11/conformance`) runs the whole `VendorAdapter` contract
and measures every `Capabilities` field in both directions. A field the
module does not match is a failing subtest that names the measured value,
so a wrong declaration is fixed by reading the failure. The suite creates
objects labelled `conf-<run id>-…` and destroys them afterwards. Run it on
a token that holds nothing you need.

The differences measured so far, one field each:

| Field | What differs |
|---|---|
| `ConcurrentSlotEnumeration` | `C_GetSlotList` from several goroutines at once (deadlocks on the ProtectToolkit-C emulator) |
| `SecondInitializeInProcess` | a second `C_Initialize` in one process |
| `HandlesSpanSessions`, `HandlesSurviveSessionClose` | the scope of an object handle |
| `ZeroDigest` | ECDSA over an all-zero digest: accepted, signed but not verified, or refused (all three seen) |
| `UnwrapHonoursExtractable` | whether the unwrap template's `CKA_EXTRACTABLE` reaches the key |
| `PrivateKeyWrapRefused` | whether a private key may be wrapped at all (partition policy on Luna) |
| `UnwrapNeedsValueLen` | whether an unwrap template needs `CKA_VALUE_LEN` (Luna does, SoftHSM2 refuses it) |
| `SerializeOnOneThread` | whether the module has to be driven from one OS thread |

## Errors

A refusal from the module carries its `CK_RV` as a `pkcs11.ReturnValue`,
so a caller tests for a code without importing the binding:

```go
if errors.Is(err, pkcs11.RVPINIncorrect) { ... }
rv, ok := pkcs11.ReturnValueOf(err) // whichever code is there
errors.Is(err, pkcs11.ReturnValue(0x80000123)) // a vendor-defined one
```

The message is the one the module's refusal always had
(`C_Login (anchor): pkcs11: 0xA0: CKR_PIN_INCORRECT`). The layer's own
refusals are sentinel errors: `ErrSessionExpired`, `ErrAdapterClosed`,
`ErrKeyNotFound`, `ErrAmbiguousLabel` and the rest in `errors.go`.

## Scope

- Asymmetric keys are EC only: P-256, P-384, P-521, ECDSA.
- Symmetric keys are AES only (128, 192, 256), for encrypt, decrypt, wrap
  and unwrap.
- No RSA, no EdDSA, no key derivation, no object import other than unwrap.

## Known limits

- **One PIN copy outside this code.** The binding,
  [miekg/pkcs11](https://github.com/miekg/pkcs11) v1.1.2, takes the PIN as
  a Go string and copies it into a C buffer that it frees without zeroing.
  [docs/threat-model.md](../docs/threat-model.md) §6.3 says why that is
  accepted.
- **nShield is untested.** Its Security World is where the login and
  key-protection model is expected to differ most from the three measured
  here, so it is the next real test of whether the interface is general.
- **PED-authenticated Luna partitions are untested.** Only password
  authentication was measured.

## License

Apache-2.0, as the rest of the repository.
