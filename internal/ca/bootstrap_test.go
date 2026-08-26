package ca_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

func testBootstrapParams(certPath string) ca.BootstrapParams {
	return ca.BootstrapParams{
		KeyLabel:     "bootstrap-test-key",
		CertPath:     certPath,
		Curve:        pk11.P256,
		RootValidity: 24 * time.Hour,
		CertTTL:      time.Hour,
	}
}

func TestBootstrap_CreatesNewCA(t *testing.T) {
	adapter, ws, resolvePIN := newTestAdapter(t)
	certPath := filepath.Join(t.TempDir(), "ca-cert.pem")

	c, err := ca.Bootstrap(context.Background(), adapter, ws, pk11.SessionOptions{}, resolvePIN, testBootstrapParams(certPath))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if !c.Certificate().IsCA {
		t.Fatal("bootstrapped certificate has IsCA=false")
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("Bootstrap did not write a certificate file at %s: %v", certPath, err)
	}
}

func TestBootstrap_LoadsExistingCAOnSecondCall(t *testing.T) {
	adapter, ws, resolvePIN := newTestAdapter(t)
	certPath := filepath.Join(t.TempDir(), "ca-cert.pem")
	params := testBootstrapParams(certPath)

	first, err := ca.Bootstrap(context.Background(), adapter, ws, pk11.SessionOptions{}, resolvePIN, params)
	if err != nil {
		t.Fatalf("Bootstrap (1st): %v", err)
	}
	second, err := ca.Bootstrap(context.Background(), adapter, ws, pk11.SessionOptions{}, resolvePIN, params)
	if err != nil {
		t.Fatalf("Bootstrap (2nd): %v", err)
	}

	if first.Certificate().SerialNumber.Cmp(second.Certificate().SerialNumber) != 0 {
		t.Fatalf("second Bootstrap produced a different certificate (serial %v vs %v) instead of loading the existing one",
			second.Certificate().SerialNumber, first.Certificate().SerialNumber)
	}
}

func TestBootstrap_KeyWithoutCertFileFails(t *testing.T) {
	adapter, ws, resolvePIN := newTestAdapter(t)
	certPath := filepath.Join(t.TempDir(), "ca-cert.pem")
	params := testBootstrapParams(certPath)

	ctx := context.Background()
	_, err := withSession(t, ctx, adapter, ws, resolvePIN, func(s *pk11.Session) (struct{}, error) {
		_, err := adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: params.Curve, Label: params.KeyLabel, Sign: true, Verify: true,
		})
		return struct{}{}, err
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// The key now exists on the HSM but certPath does not — an
	// inconsistent state Bootstrap must refuse rather than guess at.
	if _, err := ca.Bootstrap(ctx, adapter, ws, pk11.SessionOptions{}, resolvePIN, params); err == nil {
		t.Fatal("Bootstrap with a key but no cert file succeeded, want an error")
	}
}

func TestBootstrap_CertFileWithoutKeyFails(t *testing.T) {
	adapter, ws, resolvePIN := newTestAdapter(t)
	certPath := filepath.Join(t.TempDir(), "ca-cert.pem")
	params := testBootstrapParams(certPath)

	if err := os.WriteFile(certPath, []byte("not a real cert, just needs to exist"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// The cert file now exists but no matching key was ever generated on
	// the HSM — Bootstrap must refuse rather than guess at this too.
	if _, err := ca.Bootstrap(context.Background(), adapter, ws, pk11.SessionOptions{}, resolvePIN, params); err == nil {
		t.Fatal("Bootstrap with a cert file but no HSM key succeeded, want an error")
	}
}
