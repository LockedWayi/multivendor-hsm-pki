// Command hsm-pki-keytool hosts the operator-run key operations: the root
// and intermediate ceremony, intermediate re-issue, signing-key
// provisioning and inventory generation. It is a separate binary from
// cmd/hsm-pki-server because these operations touch the root key, which
// the service's configuration must never name. Both binaries share one
// PIN-handling implementation, pkcs11.SecurePIN.
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

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hsm-pki-keytool: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: hsm-pki-keytool <command> [flags]\n  commands: ceremony, reissue-intermediate, provision-signing-key, generate-inventory")
	}
	switch args[0] {
	case "ceremony":
		return runCeremonyCmd(args[1:])
	case "reissue-intermediate":
		return runReissueIntermediateCmd(args[1:])
	case "provision-signing-key":
		return runProvisionSigningKeyCmd(args[1:])
	case "generate-inventory":
		return runGenerateInventoryCmd(args[1:])
	default:
		return fmt.Errorf("unknown command %q (want: ceremony, reissue-intermediate, provision-signing-key, generate-inventory)", args[0])
	}
}

// runCeremonyCmd mirrors ca.CeremonyParams as command-line flags. It is
// kept apart from internal/config.Config: that type describes the
// service's single-token configuration and must not be able to name the
// root's token.
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
	rootKeyExtractable := fs.Bool("root-key-extractable", true, "set CKA_EXTRACTABLE on the root private key, enabling wrap-based backup (docs/key-ceremony-and-recovery.md); does not affect CKA_SENSITIVE, which is always forced true")

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
	// A re-run against a previous ceremony's output paths is a mistake.
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
		RootWorkspace:      rootWS,
		RootPIN:            pinResolver(*rootPINEnv),
		RootKeyLabel:       *rootKeyLabel,
		RootSubject:        pkix.Name{CommonName: *rootCN},
		RootCurve:          curve,
		RootCRLURL:         *rootCRLURL,
		RootCertURL:        *rootCertURL,
		RootKeyExtractable: *rootKeyExtractable,

		IntermediateWorkspace: interWS,
		IntermediatePIN:       pinResolver(*interPINEnv),
		IntermediateKeyLabel:  *interKeyLabel,
		IntermediateSubject:   pkix.Name{CommonName: *interCN},
		IntermediateCurve:     curve,
	})
	// Artifacts are written before the error is checked. RunCeremony can
	// return a valid result with an error when the root logout failed, and
	// those certificates cannot be regenerated: the key labels are taken.
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
		fmt.Println("no private key material was written anywhere; both key pairs remain on their tokens")
		if *rootKeyExtractable {
			fmt.Println("root private key: CKA_EXTRACTABLE=true, eligible for wrap-based backup (docs/key-ceremony-and-recovery.md)")
		} else {
			fmt.Println("root private key: CKA_EXTRACTABLE=false, no wrap-based backup; recovery on loss is a fresh ceremony and cross-signing")
		}
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

// findWorkspace resolves a token by the label an operator typed,
// optionally narrowed by serial. PKCS#11 does not require labels to be
// unique. A label matching more than one token is refused, and the error
// lists the candidates with their serials.
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
			"label %q matches %d tokens; refusing to guess which one to use. Re-run with the matching -...-workspace-serial flag. Candidates:%s",
			label, len(matches), b.String())
	}
}

// pinResolver reads the PIN from the named environment variable at the
// point of use. It is never cached or logged.
func pinResolver(envVar string) ca.PINResolver {
	return func() ([]byte, error) {
		pin := os.Getenv(envVar)
		if pin == "" {
			return nil, fmt.Errorf("environment variable %s is not set", envVar)
		}
		return []byte(pin), nil
	}
}

// writeCertPEM writes der as a PEM certificate file, mode 0644: it holds
// no private key material.
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
