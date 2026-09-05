package main

// The routine half of CA-key rotation (the key lifecycle,
// docs/key-ceremony-and-recovery.md §4.1.1): sign a new intermediate under
// the root that already exists, without touching the root itself.
//
// It is a separate subcommand from `ceremony` rather than a flag on it,
// because the two differ in exactly the way that matters: `ceremony`
// creates a root, this never can. A shared command with a "reuse the
// existing root" switch would put the operation that rebuilds every trust
// store one mistyped argument away from the operation that does not.

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	"github.com/LockedWayi/hsm-pki-platform/internal/config"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

func runReissueIntermediateCmd(args []string) error {
	fs := flag.NewFlagSet("reissue-intermediate", flag.ExitOnError)

	adapterName := fs.String("adapter", config.AdapterSoftHSM2, "vendor adapter: \"softhsm2\" or \"protectserver\"")
	modulePath := fs.String("module", "", "path to the PKCS#11 module (.so)")
	curveName := fs.String("curve", "P-256", "EC curve for the new intermediate key pair: P-256, P-384, or P-521")
	rootCurveName := fs.String("root-curve", "", "EC curve the EXISTING root key was generated on; defaults to -curve")

	rootWorkspaceLabel := fs.String("root-workspace", "", "token label the existing root key lives on")
	rootWorkspaceSerial := fs.String("root-workspace-serial", "", "token serial number, to disambiguate when several tokens share the root label")
	rootPINEnv := fs.String("root-pin-env", "", "environment variable holding the root token's PIN")
	rootKeyLabel := fs.String("root-key-label", "", "CKA_LABEL of the EXISTING root key (this command never creates one)")
	rootCertIn := fs.String("root-cert", "", "path to the existing root certificate PEM, kept from the original ceremony")
	rootCRLURL := fs.String("root-crl-url", "", "URL the root CRL is served from (becomes the new intermediate's CRL distribution point)")
	rootCertURL := fs.String("root-cert-url", "", "URL the root certificate is served from (becomes the new intermediate's AIA CA-Issuers pointer)")

	interWorkspaceLabel := fs.String("intermediate-workspace", "", "token label the new intermediate key pair is generated on")
	interWorkspaceSerial := fs.String("intermediate-workspace-serial", "", "token serial number, to disambiguate when several tokens share the intermediate label")
	interPINEnv := fs.String("intermediate-pin-env", "", "environment variable holding the intermediate token's PIN")
	interKeyLabel := fs.String("intermediate-key-label", "", "CKA_LABEL for the NEW intermediate key pair — the next version, e.g. ca-intermediate-key-v2")
	interCN := fs.String("intermediate-cn", "hsm-pki-platform Intermediate CA", "new intermediate certificate subject common name")
	interCertOut := fs.String("intermediate-cert-out", "", "path to write the new intermediate certificate PEM")
	interValidity := fs.Duration("intermediate-validity", 0, "how long the new intermediate is valid for; defaults to the package default (5 years)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	curve, err := config.ParseCurve(*curveName)
	if err != nil {
		return err
	}
	// The root's curve is separate from the new intermediate's because
	// rotation is exactly the moment they may legitimately differ: moving
	// the intermediate to P-384 while the root stays on the curve it was
	// generated on years ago is a rotation, not a mistake.
	rootCurve := curve
	if *rootCurveName != "" {
		if rootCurve, err = config.ParseCurve(*rootCurveName); err != nil {
			return fmt.Errorf("-root-curve: %w", err)
		}
	}

	for name, v := range map[string]string{
		"-module": *modulePath, "-root-workspace": *rootWorkspaceLabel, "-root-pin-env": *rootPINEnv,
		"-root-key-label": *rootKeyLabel, "-root-cert": *rootCertIn,
		"-root-crl-url": *rootCRLURL, "-root-cert-url": *rootCertURL,
		"-intermediate-workspace": *interWorkspaceLabel, "-intermediate-pin-env": *interPINEnv,
		"-intermediate-key-label": *interKeyLabel, "-intermediate-cert-out": *interCertOut,
	} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	// Refuse to clobber an existing artifact. A re-run against the previous
	// intermediate's output path is the mistake this catches, and it is a
	// costly one: that file is the certificate still serving traffic
	// through the transition window.
	if _, err := os.Stat(*interCertOut); err == nil {
		return fmt.Errorf("refusing to overwrite existing file %s", *interCertOut)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking output path %s: %w", *interCertOut, err)
	}

	rootCert, err := readCertPEM(*rootCertIn)
	if err != nil {
		return err
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

	result, reissueErr := ca.ReissueIntermediate(ctx, adapter, pk11.DefaultSessionOptions(), ca.ReissueIntermediateParams{
		RootWorkspace: rootWS,
		RootPIN:       pinResolver(*rootPINEnv),
		RootKeyLabel:  *rootKeyLabel,
		RootCurve:     rootCurve,
		RootCert:      rootCert,
		RootCRLURL:    *rootCRLURL,
		RootCertURL:   *rootCertURL,

		IntermediateWorkspace: interWS,
		IntermediatePIN:       pinResolver(*interPINEnv),
		IntermediateKeyLabel:  *interKeyLabel,
		IntermediateSubject:   pkix.Name{CommonName: *interCN},
		IntermediateCurve:     curve,
		IntermediateValidity:  *interValidity,
	})
	// Written before the error is checked, for the same reason the ceremony
	// does it: ReissueIntermediate can return a valid certificate alongside
	// a logout failure, and that certificate cannot be regenerated because
	// the new key label is now in use.
	if result != nil {
		if err := writeCertPEM(*interCertOut, result.IntermediateCertDER); err != nil {
			return err
		}
		fmt.Printf("new intermediate certificate written: %s\n", *interCertOut)
		fmt.Println("no private key material was written anywhere — the new key pair remains on its HSM token")
		fmt.Printf("the previous intermediate is NOT revoked by this operation: it stays valid until you revoke it\n" +
			" and publish a root CRL saying so, which is the transition window\n")
	}
	if reissueErr != nil {
		return fmt.Errorf("reissue-intermediate: %w", reissueErr)
	}
	return nil
}

// readCertPEM reads exactly one PEM certificate from path.
//
// A file carrying a second block is rejected rather than silently reduced
// to its first: the likely way that happens is an operator passing a chain
// where a single root was wanted, and picking the first block would make
// the choice by file order, which is nobody's decision.
func readCertPEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s does not contain a PEM block", path)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%s contains more than one PEM block; it must hold exactly one certificate, not a chain", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s holds a %q PEM block, want CERTIFICATE", path, block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cert, nil
}
