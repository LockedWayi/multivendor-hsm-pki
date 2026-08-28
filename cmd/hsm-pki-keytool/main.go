// Command hsm-pki-keytool hosts operator-run, one-time HSM key ceremonies —
// starting with the root/intermediate CA bootstrap (docs/phases/
// phase-3b-pki-hardening.md, sub-task 3b.1). It is deliberately a separate
// binary from cmd/hsm-pki-server: the operations here touch the root key,
// which the online service's configuration must never reference, and a
// single PIN-handling implementation (pkcs11.SecurePIN) shared between the
// two binaries is safer than reimplementing it wherever a ceremony is
// needed. Later signing-key lifecycle operations (Phase 4.8) are expected
// to land as further subcommands of this same tool.
package main

import (
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	"github.com/LockedWayi/hsm-pki-platform/internal/config"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hsm-pki-keytool: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: hsm-pki-keytool <command> [flags]\n  commands: ceremony")
	}
	switch args[0] {
	case "ceremony":
		return runCeremonyCmd(args[1:])
	default:
		return fmt.Errorf("unknown command %q (want: ceremony)", args[0])
	}
}

// ceremonyFlags mirrors ca.CeremonyParams field-for-field, as command-line
// flags — see that type's doc comment for what each one means. Kept
// separate from internal/config.Config deliberately: that type describes
// the online service's single-token runtime configuration, and folding a
// two-token, operator-run ceremony into the same schema would blur a
// distinction this platform depends on (the service's configuration must
// never be able to name the root's token at all).
func runCeremonyCmd(args []string) error {
	fs := flag.NewFlagSet("ceremony", flag.ExitOnError)

	adapterName := fs.String("adapter", config.AdapterSoftHSM2, "vendor adapter: \"softhsm2\" or \"protectserver\"")
	modulePath := fs.String("module", "", "path to the PKCS#11 module (.so)")
	curveName := fs.String("curve", "P-256", "EC curve for both key pairs: P-256, P-384, or P-521")

	rootWorkspaceLabel := fs.String("root-workspace", "", "token label the root key pair is generated on")
	rootWorkspaceSerial := fs.String("root-workspace-serial", "", "token serial number, to disambiguate when several tokens share the root label")
	rootPINEnv := fs.String("root-pin-env", "", "environment variable holding the root token's PIN")
	rootKeyLabel := fs.String("root-key-label", "", "CKA_LABEL for the root key pair (versioned, e.g. ca-root-key-v1)")
	rootCN := fs.String("root-cn", "hsm-pki-platform Root CA", "root certificate subject common name")
	rootCertOut := fs.String("root-cert-out", "", "path to write the root certificate PEM")
	rootCRLOut := fs.String("root-crl-out", "", "path to write the root CRL PEM")
	rootCRLURL := fs.String("root-crl-url", "", "URL the root CRL will be served from (becomes the intermediate's CRL distribution point)")
	rootCertURL := fs.String("root-cert-url", "", "URL the root certificate will be served from (becomes the intermediate's AIA CA-Issuers pointer)")

	interWorkspaceLabel := fs.String("intermediate-workspace", "", "token label the intermediate key pair is generated on")
	interWorkspaceSerial := fs.String("intermediate-workspace-serial", "", "token serial number, to disambiguate when several tokens share the intermediate label")
	interPINEnv := fs.String("intermediate-pin-env", "", "environment variable holding the intermediate token's PIN")
	interKeyLabel := fs.String("intermediate-key-label", "", "CKA_LABEL for the intermediate key pair (versioned, e.g. ca-intermediate-key-v1)")
	interCN := fs.String("intermediate-cn", "hsm-pki-platform Intermediate CA", "intermediate certificate subject common name")
	interCertOut := fs.String("intermediate-cert-out", "", "path to write the intermediate certificate PEM")

	if err := fs.Parse(args); err != nil {
		return err
	}

	curve, err := config.ParseCurve(*curveName)
	if err != nil {
		return err
	}
	for name, v := range map[string]string{
		"-module": *modulePath, "-root-workspace": *rootWorkspaceLabel, "-root-pin-env": *rootPINEnv,
		"-root-key-label": *rootKeyLabel, "-root-cert-out": *rootCertOut, "-root-crl-out": *rootCRLOut,
		"-root-crl-url": *rootCRLURL, "-root-cert-url": *rootCertURL,
		"-intermediate-workspace": *interWorkspaceLabel, "-intermediate-pin-env": *interPINEnv,
		"-intermediate-key-label": *interKeyLabel, "-intermediate-cert-out": *interCertOut,
	} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	// Refuse to clobber existing artifacts silently — a re-run against
	// output paths from a previous ceremony is almost certainly a mistake,
	// not an intentional overwrite.
	for _, path := range []string{*rootCertOut, *rootCRLOut, *interCertOut} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing file %s", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("checking output path %s: %w", path, err)
		}
	}

	adapter, err := newVendorAdapter(*adapterName, *modulePath)
	if err != nil {
		return err
	}
	defer adapter.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rootWS, err := findWorkspace(ctx, adapter, *rootWorkspaceLabel, *rootWorkspaceSerial)
	if err != nil {
		return fmt.Errorf("root: %w", err)
	}
	interWS, err := findWorkspace(ctx, adapter, *interWorkspaceLabel, *interWorkspaceSerial)
	if err != nil {
		return fmt.Errorf("intermediate: %w", err)
	}

	result, ceremonyErr := ca.RunCeremony(ctx, adapter, pk11.DefaultSessionOptions(), ca.CeremonyParams{
		RootWorkspace: rootWS,
		RootPIN:       pinResolver(*rootPINEnv),
		RootKeyLabel:  *rootKeyLabel,
		RootSubject:   pkix.Name{CommonName: *rootCN},
		RootCurve:     curve,
		RootCRLURL:    *rootCRLURL,
		RootCertURL:   *rootCertURL,

		IntermediateWorkspace: interWS,
		IntermediatePIN:       pinResolver(*interPINEnv),
		IntermediateKeyLabel:  *interKeyLabel,
		IntermediateSubject:   pkix.Name{CommonName: *interCN},
		IntermediateCurve:     curve,
	})
	// Artifacts are written before the error is checked, deliberately.
	// RunCeremony can return a non-nil error alongside a valid result — a
	// token that failed to log out after the certificates were already
	// signed is the case that matters — and those certificates cannot be
	// regenerated, because the ceremony's key labels are now in use. Losing
	// them to an early return would be unrecoverable; writing them and then
	// reporting the error is not.
	if result != nil {
		if err := writeCertPEM(*rootCertOut, result.RootCertDER); err != nil {
			return err
		}
		if err := writeCertPEM(*interCertOut, result.IntermediateCertDER); err != nil {
			return err
		}
		if err := writeCRLPEM(*rootCRLOut, result.RootCRLDER); err != nil {
			return err
		}
		fmt.Printf("ceremony artifacts written:\n  root certificate:         %s\n  intermediate certificate: %s\n  root CRL:                 %s\n",
			*rootCertOut, *interCertOut, *rootCRLOut)
		fmt.Println("no private key material was written anywhere — both key pairs remain on their respective HSM tokens")
	}
	if ceremonyErr != nil {
		return fmt.Errorf("ceremony: %w", ceremonyErr)
	}
	return nil
}

func newVendorAdapter(adapterName, modulePath string) (pk11.VendorAdapter, error) {
	switch adapterName {
	case config.AdapterSoftHSM2:
		return pk11.NewSoftHSM2Adapter(modulePath)
	case config.AdapterProtectServer:
		return pk11.NewProtectServerAdapter(modulePath)
	default:
		return nil, fmt.Errorf("unknown -adapter %q (want %q or %q)", adapterName, config.AdapterSoftHSM2, config.AdapterProtectServer)
	}
}

// findWorkspace resolves a token by the label an operator typed, optionally
// narrowed by serial number.
//
// Label is the addressing key because it is what a human knows; serial is
// the identity key because PKCS#11 does not require labels to be unique (see
// pkcs11.Workspace). When a label matches more than one token, this refuses
// to choose — an earlier version returned the first match, which on a token
// set with a duplicated label means generating CA keys on whichever token
// the driver happened to enumerate first. The error lists the candidates and
// their serials so the operator can re-run with the disambiguating flag.
func findWorkspace(ctx context.Context, adapter pk11.VendorAdapter, label, serial string) (pk11.Workspace, error) {
	workspaces, err := adapter.Workspaces(ctx)
	if err != nil {
		return pk11.Workspace{}, err
	}

	var matches []pk11.Workspace
	for _, w := range workspaces {
		if w.Label != label {
			continue
		}
		if serial != "" && w.Serial != serial {
			continue
		}
		matches = append(matches, w)
	}

	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		if serial != "" {
			return pk11.Workspace{}, fmt.Errorf("no token with label %q and serial %q found", label, serial)
		}
		return pk11.Workspace{}, fmt.Errorf("token %q not found", label)
	default:
		var b strings.Builder
		for _, w := range matches {
			fmt.Fprintf(&b, "\n  serial %q (slot %d)", w.Serial, w.SlotID)
		}
		return pk11.Workspace{}, fmt.Errorf(
			"label %q matches %d tokens — refusing to guess which one to use; re-run with the matching -...-workspace-serial flag. Candidates:%s",
			label, len(matches), b.String())
	}
}

// pinResolver reads the PIN from the named environment variable at the
// point of use — never cached, never logged (CLAUDE.md §3.1).
func pinResolver(envVar string) ca.PINResolver {
	return func() ([]byte, error) {
		pin := os.Getenv(envVar)
		if pin == "" {
			return nil, fmt.Errorf("environment variable %s is not set", envVar)
		}
		return []byte(pin), nil
	}
}

// writeCertPEM writes der as a PEM-encoded certificate file. Contains no
// private key material — 0644 is appropriate, the same reasoning as
// internal/ca.Bootstrap's own writeCertPEM.
func writeCertPEM(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// writeCRLPEM writes der as a PEM-encoded X509 CRL file.
func writeCRLPEM(path string, der []byte) error {
	block := &pem.Block{Type: "X509 CRL", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
