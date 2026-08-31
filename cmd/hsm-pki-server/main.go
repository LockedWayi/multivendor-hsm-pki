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
	healthcheck := flag.Bool("healthcheck", false,
		"probe this container's own /healthz and exit 0 (healthy) or 1 (not), then stop; this is what the image's HEALTHCHECK runs, because the image has no shell to invoke a tool from")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Handled before anything else starts: this mode opens no HSM session,
	// no store, and no listener. It reads the config only to learn which
	// address the service it is probing was told to bind.
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
	// No secret material in this line by construction: ws.Label is an
	// operator-assigned token label, never the PIN (CLAUDE.md §3.1).
	logger.Info("connected to HSM",
		"adapter", cfg.PKCS11.Adapter,
		"workspace", ws.Label,
	)

	// Composed here rather than inside internal/ca: the paths belong to the
	// HTTP surface (internal/api owns the routes), the origin belongs to the
	// operator's configuration, and the CA only ever sees finished URLs. It
	// is the composition root's job to join the two.
	leafDist := api.LeafDistributionFor(cfg.CA.BaseURL)

	// The service loads a ceremony-produced intermediate and never creates a
	// CA of its own. A configuration pointing it at a self-signed (root)
	// certificate fails here rather than starting in a degraded posture
	// (CLAUDE.md §3.4, docs/phases/phase-3b-pki-hardening.md).
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
	// The two URLs are logged because they are the one part of an issued
	// certificate an operator cannot fix afterward: every leaf signed by
	// this process will carry them verbatim. Seeing them at startup is the
	// last cheap chance to notice a wrong base URL. Both are public
	// endpoints, so nothing here is sensitive (CLAUDE.md §3.1).
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

	// The store outlives the process it is opened in — that is its whole
	// purpose. Revocations recorded here are still revoked after a restart,
	// which the in-memory registry this replaced could not promise
	// (docs/phases/phase-3b-pki-hardening.md, sub-task 3b.3).
	records, err := store.OpenSQLite(ctx, cfg.CA.StorePath, logger, cfg.CA.CRLFloor())
	if err != nil {
		return err
	}
	defer records.Close()

	httpServer := &http.Server{
		Addr:    cfg.Server.ListenAddr,
		Handler: api.NewServer(caInstance, adapter, ws, records, time.Duration(cfg.CA.CRLValidityHours)*time.Hour, rootArtifacts, logger),
		// http.TimeoutHandler (internal/api) bounds how long a handler may
		// run once it has been dispatched. It does nothing about a client
		// that never finishes sending, which is the Slowloris shape: open
		// many connections, dribble headers, and hold a goroutine and a
		// file descriptor each for as long as the server is willing to
		// wait. With no timeouts set, that is forever.
		//
		// ReadHeaderTimeout is the one that closes that specific hole;
		// ReadTimeout and WriteTimeout bound a slow body and a slow reader
		// respectively, and IdleTimeout bounds a kept-alive connection
		// between requests. All four are deliberately well above
		// api.requestTimeout, so the handler's own deadline stays the thing
		// that fires first in normal operation and these only catch a
		// client that is not making progress at all.
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
	// A label match that is not unique is ambiguous, and this refuses to
	// choose rather than taking the first hit. PKCS#11 places no uniqueness
	// constraint on CKA_LABEL (CLAUDE.md §3.8), so "first match" means the
	// service authenticates whichever token the driver happened to
	// enumerate first — and on the next boot, possibly the other one. That
	// is a decision nobody made, about which token holds the CA's key.
	// cmd/hsm-pki-keytool already fails closed here; this is the same rule
	// on the service side, where it had been missed.
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
			"workspace label %q matches %d tokens (serials %s); labels are not unique in PKCS#11, so this cannot choose one — give the token a distinct label",
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
// CRL off disk and returns their DER, which is what the service serves at
// the URLs the intermediate's CDP and AIA extensions point at.
//
// PEM on disk, DER on the wire, and the asymmetry is deliberate: PEM is
// what an operator copies between hosts and what the ceremony writes, while
// RFC 2585 §3 says a client following one of those URLs gets a single DER
// object (see api.ContentTypeCert / api.ContentTypeCRL). Converting once
// here keeps both audiences served without either format leaking into the
// other's territory.
//
// Both are required and both are validated here rather than trusted
// blindly: serving a truncated or wrong-typed file at a CRL distribution
// point produces a relying party that cannot check the intermediate's
// revocation status, and it should fail at startup where an operator sees
// it, not silently at a verifier somewhere else (CLAUDE.md §3.4).
func loadRootArtifacts(cfg *config.Config) (api.RootArtifacts, error) {
	certDER, err := readPEMFile(cfg.CA.RootCertPath, "CERTIFICATE")
	if err != nil {
		return api.RootArtifacts{}, err
	}
	crlDER, err := readPEMFile(cfg.CA.RootCRLPath, "X509 CRL")
	if err != nil {
		return api.RootArtifacts{}, err
	}
	// Parse what will be served, rather than trusting that a well-formed
	// PEM envelope contains a well-formed object. The envelope only proves
	// the base64 decoded.
	if _, err := x509.ParseCertificate(certDER); err != nil {
		return api.RootArtifacts{}, errors.New(cfg.CA.RootCertPath + " is not a parseable certificate: " + err.Error())
	}
	if _, err := x509.ParseRevocationList(crlDER); err != nil {
		return api.RootArtifacts{}, errors.New(cfg.CA.RootCRLPath + " is not a parseable CRL: " + err.Error())
	}
	return api.RootArtifacts{CertDER: certDER, CRLDER: crlDER}, nil
}

// readPEMFile returns the DER inside the single PEM block in path.
//
// "Single" is enforced, not assumed. A file carrying a second block is
// rejected rather than silently reduced to its first: the most likely way
// that happens is an operator pasting a whole chain into root_cert_path,
// and quietly serving only the first certificate of a bundle the operator
// believed was complete is exactly the kind of half-correct behaviour that
// surfaces at a relying party instead of at startup (CLAUDE.md §3.4).
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
