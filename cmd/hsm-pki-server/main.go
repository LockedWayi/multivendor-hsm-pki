// Command hsm-pki-server runs the CA's HTTP service.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/api"
	"github.com/LockedWayi/hsm-pki-platform/internal/config"
	pkcs11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
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

	httpServer := &http.Server{
		Addr:    cfg.Server.ListenAddr,
		Handler: api.NewServer(),
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

// verifyHSMConnection proves, before the service accepts any traffic, that
// the configured adapter can actually reach its workspace and log in — a
// wrong PIN or an unreachable module fails the process at startup rather
// than surfacing as a 500 on the first request (CLAUDE.md §3.4, fail
// closed). The session opened here is not kept: the CA signer (Phase 2
// sub-task 2.2) opens its own session per operation, since a single
// session held for the service's lifetime would eventually hit its own
// idle timeout or max TTL and start failing closed on every subsequent
// call.
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

	session, err := adapter.OpenSession(ctx, ws, cfg.PKCS11.SessionOptions)
	if err != nil {
		return pkcs11.Workspace{}, err
	}
	defer adapter.CloseSession(ctx, session)

	pin, err := cfg.ResolvePIN()
	if err != nil {
		return pkcs11.Workspace{}, err
	}
	if err := adapter.Login(ctx, session, pin, pkcs11.RoleUser); err != nil {
		return pkcs11.Workspace{}, err
	}
	defer adapter.Logout(ctx, session)

	return ws, nil
}

type errWorkspaceNotFound string

func (e errWorkspaceNotFound) Error() string {
	return "workspace " + string(e) + " not found"
}
