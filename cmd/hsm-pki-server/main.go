// Command hsm-pki-server runs the CA's HTTP service.
package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/api"
	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	"github.com/LockedWayi/hsm-pki-platform/internal/config"
	pkcs11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
	"github.com/LockedWayi/hsm-pki-platform/internal/store"
)

// shutdownGrace bounds how long the server waits for in-flight requests to
// drain before forcing shutdown.
const shutdownGrace = 10 * time.Second

func main() {
	configPath := flag.String("config", "config.yaml", "path to the service config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
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
	// No secret material in this line by construction: ws.Label is an
	// operator-assigned token label, never the PIN (CLAUDE.md §3.1).
	logger.Info("connected to HSM",
		"adapter", cfg.PKCS11.Adapter,
		"workspace", ws.Label,
	)

	// The service loads a ceremony-produced intermediate and never creates a
	// CA of its own. A configuration pointing it at a self-signed (root)
	// certificate fails here rather than starting in a degraded posture
	// (CLAUDE.md §3.4, docs/phases/phase-3b-pki-hardening.md).
	caInstance, err := ca.LoadIntermediate(ctx, adapter, ws, cfg.PKCS11.SessionOptions, cfg.ResolvePIN, ca.LoadIntermediateParams{
		KeyLabel: cfg.CA.IntermediateKeyLabel,
		CertPath: cfg.CA.IntermediateCertPath,
		Curve:    cfg.CA.Curve(),
		CertTTL:  time.Duration(cfg.CA.CertTTLHours) * time.Hour,
	})
	if err != nil {
		return err
	}
	logger.Info("intermediate CA ready",
		"subject", caInstance.Certificate().Subject.String(),
		"serial", caInstance.Certificate().SerialNumber.String(),
		"not_after", caInstance.Certificate().NotAfter,
	)

	rootArtifacts, err := loadRootArtifacts(cfg)
	if err != nil {
		return err
	}

	// The store outlives the process it is opened in — that is its whole
	// purpose. Revocations recorded here are still revoked after a restart,
	// which the in-memory registry this replaced could not promise
	// (docs/phases/phase-3b-pki-hardening.md, sub-task 3b.3).
	records, err := store.OpenSQLite(ctx, cfg.CA.StorePath, logger)
	if err != nil {
		return err
	}
	defer records.Close()

	httpServer := &http.Server{
		Addr:    cfg.Server.ListenAddr,
		Handler: api.NewServer(caInstance, adapter, ws, records, time.Duration(cfg.CA.CRLValidityHours)*time.Hour, rootArtifacts, logger),
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

// verifyHSMConnection resolves the configured workspace and establishes the
// token login, before the service accepts any traffic. A wrong PIN or an
// unreachable module fails the process at startup rather than surfacing as
// a 500 on the first request (CLAUDE.md §3.4, fail closed).
//
// The login it establishes is not torn down here — it is the service's
// anchor login, held by the adapter for the process's lifetime and released
// by adapter.Close during shutdown. PKCS#11 authenticates a token for the
// whole application rather than per session, so every session the CA opens
// afterward inherits this and needs no login of its own; see
// internal/pkcs11/tokenlogin.go for why the alternative (login and logout
// around each operation) cannot survive concurrent requests.
func verifyHSMConnection(ctx context.Context, cfg *config.Config, adapter pkcs11.VendorAdapter) (pkcs11.Workspace, error) {
	vendor, err := cfg.Vendor()
	if err != nil {
		return pkcs11.Workspace{}, err
	}

	workspaces, err := adapter.Workspaces(ctx)
	if err != nil {
		return pkcs11.Workspace{}, err
	}
	var ws pkcs11.Workspace
	found := false
	for _, w := range workspaces {
		if w.Label == vendor.WorkspaceLabel {
			ws, found = w, true
			break
		}
	}
	if !found {
		return pkcs11.Workspace{}, errWorkspaceNotFound(vendor.WorkspaceLabel)
	}

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
// CRL off disk so the service can republish them at the URLs the
// intermediate's CDP and AIA extensions point at.
//
// Both are required and both are validated as PEM here rather than trusted
// blindly: serving a truncated or wrong-typed file at a CRL distribution
// point produces a relying party that cannot check the intermediate's
// revocation status, and it should fail at startup where an operator sees
// it, not silently at a verifier somewhere else (CLAUDE.md §3.4).
func loadRootArtifacts(cfg *config.Config) (api.RootArtifacts, error) {
	certPEM, err := readPEMFile(cfg.CA.RootCertPath, "CERTIFICATE")
	if err != nil {
		return api.RootArtifacts{}, err
	}
	crlPEM, err := readPEMFile(cfg.CA.RootCRLPath, "X509 CRL")
	if err != nil {
		return api.RootArtifacts{}, err
	}
	return api.RootArtifacts{CertPEM: certPEM, CRLPEM: crlPEM}, nil
}

func readPEMFile(path, wantType string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New(path + " does not contain a PEM block")
	}
	if block.Type != wantType {
		return nil, errors.New(path + " contains a " + block.Type + " PEM block, want " + wantType)
	}
	return data, nil
}

type errWorkspaceNotFound string

func (e errWorkspaceNotFound) Error() string {
	return "workspace " + string(e) + " not found"
}
