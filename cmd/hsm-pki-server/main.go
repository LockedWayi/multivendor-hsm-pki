// Command hsm-pki-server runs the CA's HTTP service.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
	pkcs11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

// shutdownGrace bounds how long the server waits for in-flight requests to
// drain before forcing shutdown.
const shutdownGrace = 10 * time.Second

func main() {
	configPath := flag.String("config", "config.yaml", "path to the service config file")
	healthcheck := flag.Bool("healthcheck", false,
		"probe this container's own /healthz and exit 0 (healthy) or 1 (not), then stop; this is what the image's HEALTHCHECK runs, because the image has no shell to invoke a tool from")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// This mode opens no token, no store and no listener. It reads the
	// config only for the listen address.
	if *healthcheck {
		cfg, err := config.Load(*configPath)
		if err == nil {
			err = runHealthcheck(cfg.Server.ListenAddr)
		}
		if err != nil {
			logger.Error("healthcheck failed", "error", err)
			os.Exit(1)
		}
		return
	}

	if err := run(*configPath, logger); err != nil {
		logger.Error("hsm-pki-server exited with an error", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	adapter, err := cfg.NewVendorAdapter()
	if err != nil {
		return err
	}
	defer adapter.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ws, err := verifyHSMConnection(ctx, cfg, adapter)
	if err != nil {
		return err
	}
	// ws.Label is an operator-assigned token label, never the PIN.
	logger.Info("connected to HSM",
		"adapter", cfg.PKCS11.Adapter,
		"workspace", ws.Label,
	)

	// The paths belong to internal/api and the origin to the operator; the
	// CA only sees finished URLs.
	leafDist := api.LeafDistributionFor(cfg.CA.BaseURL)

	// The service loads a ceremony-produced intermediate and never creates
	// a CA. A self-signed certificate fails here.
	caInstance, err := ca.LoadIntermediate(ctx, adapter, ws, cfg.PKCS11.SessionOptions, cfg.ResolvePIN, ca.LoadIntermediateParams{
		KeyLabel:     cfg.CA.IntermediateKeyLabel,
		CertPath:     cfg.CA.IntermediateCertPath,
		Curve:        cfg.CA.Curve(),
		CertTTL:      time.Duration(cfg.CA.CertTTLHours) * time.Hour,
		Distribution: leafDist,
	})
	if err != nil {
		return err
	}
	// The two URLs are logged because every leaf will carry them and they
	// cannot be fixed afterwards. Both are public.
	logger.Info("intermediate CA ready",
		"subject", caInstance.Certificate().Subject.String(),
		"serial", caInstance.Certificate().SerialNumber.String(),
		"not_after", caInstance.Certificate().NotAfter,
		"leaf_crl_url", leafDist.CRLURL,
		"leaf_issuer_url", leafDist.IssuerCertURL,
	)

	rootArtifacts, err := loadRootArtifacts(cfg)
	if err != nil {
		return err
	}

	// Revocations recorded here survive a restart.
	records, err := store.OpenSQLite(ctx, cfg.CA.StorePath, logger, cfg.CA.CRLFloor())
	if err != nil {
		return err
	}
	defer records.Close()

	httpServer := &http.Server{
		Addr:    cfg.Server.ListenAddr,
		Handler: api.NewServer(caInstance, adapter, ws, records, time.Duration(cfg.CA.CRLValidityHours)*time.Hour, rootArtifacts, logger),
		// http.TimeoutHandler bounds a dispatched handler. It does nothing
		// about a client that never finishes sending its headers, which is
		// the Slowloris shape. ReadHeaderTimeout closes that. All four are
		// well above api.requestTimeout, so the handler's own deadline
		// fires first in normal operation.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Server.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining in-flight requests")
	case err := <-serveErr:
		if err != nil {
			return err
		}
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return err
	}
	logger.Info("shutdown complete")
	return nil
}

// verifyHSMConnection resolves the configured workspace and establishes
// the token login before the service accepts traffic. A wrong PIN or an
// unreachable module fails the process at startup. The login is the
// service's anchor login, held by the adapter for the process lifetime;
// see internal/pkcs11/tokenlogin.go.
func verifyHSMConnection(ctx context.Context, cfg *config.Config, adapter pkcs11.VendorAdapter) (pkcs11.Workspace, error) {
	vendor, err := cfg.Vendor()
	if err != nil {
		return pkcs11.Workspace{}, err
	}

	workspaces, err := adapter.Workspaces(ctx)
	if err != nil {
		return pkcs11.Workspace{}, err
	}
	// PKCS#11 places no uniqueness constraint on CKA_LABEL. A label that
	// matches more than one token is refused rather than resolved to the
	// first hit, which would let enumeration order decide which token holds
	// the CA's key.
	var matches []pkcs11.Workspace
	for _, w := range workspaces {
		if w.Label == vendor.WorkspaceLabel {
			matches = append(matches, w)
		}
	}
	if len(matches) == 0 {
		return pkcs11.Workspace{}, errWorkspaceNotFound(vendor.WorkspaceLabel)
	}
	if len(matches) > 1 {
		serials := make([]string, 0, len(matches))
		for _, w := range matches {
			serials = append(serials, w.Serial)
		}
		return pkcs11.Workspace{}, fmt.Errorf(
			"workspace label %q matches %d tokens (serials %s); labels are not unique in PKCS#11, so this cannot choose one; give the token a distinct label",
			vendor.WorkspaceLabel, len(matches), strings.Join(serials, ", "))
	}
	ws := matches[0]

	pin, err := cfg.ResolvePIN()
	if err != nil {
		return pkcs11.Workspace{}, err
	}
	if err := adapter.LoginToken(ctx, ws, pin, pkcs11.RoleUser); err != nil {
		return pkcs11.Workspace{}, err
	}

	return ws, nil
}

// loadRootArtifacts reads the ceremony's public root certificate and root
// CRL and returns their DER, which is what the service serves at the URLs
// the intermediate's CDP and AIA point at. PEM on disk, DER on the wire
// (RFC 2585 §3). Both are parsed here, so a truncated or wrong-typed file
// fails at startup rather than at a relying party.
func loadRootArtifacts(cfg *config.Config) (api.RootArtifacts, error) {
	certDER, err := readPEMFile(cfg.CA.RootCertPath, "CERTIFICATE")
	if err != nil {
		return api.RootArtifacts{}, err
	}
	crlDER, err := readPEMFile(cfg.CA.RootCRLPath, "X509 CRL")
	if err != nil {
		return api.RootArtifacts{}, err
	}
	// The PEM envelope only proves the base64 decoded.
	if _, err := x509.ParseCertificate(certDER); err != nil {
		return api.RootArtifacts{}, errors.New(cfg.CA.RootCertPath + " is not a parseable certificate: " + err.Error())
	}
	if _, err := x509.ParseRevocationList(crlDER); err != nil {
		return api.RootArtifacts{}, errors.New(cfg.CA.RootCRLPath + " is not a parseable CRL: " + err.Error())
	}
	return api.RootArtifacts{CertDER: certDER, CRLDER: crlDER}, nil
}

// readPEMFile returns the DER inside the single PEM block in path. A file
// with a second block is rejected: an operator pasting a chain into
// root_cert_path would otherwise be served only its first certificate.
func readPEMFile(path, wantType string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New(path + " does not contain a PEM block")
	}
	if block.Type != wantType {
		return nil, errors.New(path + " contains a " + block.Type + " PEM block, want " + wantType)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New(path + " contains more than one PEM block; it must hold exactly one " + wantType)
	}
	return block.Bytes, nil
}

type errWorkspaceNotFound string

func (e errWorkspaceNotFound) Error() string {
	return "workspace " + string(e) + " not found"
}
