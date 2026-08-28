package api_test

// Sub-task 2.4's tests, like the rest of Phase 2, run against SoftHSM2 only
// — see the "Decide before starting" entry in docs/phases/phase-2-ca-core.md.

import (
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/api"
	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

func requireSoftHSM2(t *testing.T) string {
	t.Helper()
	modulePath := os.Getenv("SOFTHSM2_MODULE")
	if modulePath == "" {
		modulePath = "/usr/lib/softhsm/libsofthsm2.so"
	}
	if _, err := os.Stat(modulePath); err != nil {
		t.Skip("SoftHSM2 module not found — run inside the dev container (see CONTRIBUTING.md)")
	}
	return modulePath
}

// newTestCA provisions two SoftHSM2 tokens, runs a real root ceremony over
// them, and returns the **intermediate** CA the service is built on, plus
// the adapter and workspace callers need for the /readyz probe and the
// public root artifacts the server republishes.
//
// It used to bootstrap a self-signed root, matching what the service did
// before Phase 3b. That configuration is now refused at startup
// (ca.LoadIntermediate), so testing the HTTP surface against one would
// exercise a deployment this platform rejects.
func newTestCA(t *testing.T) (*ca.CA, pk11.VendorAdapter, pk11.Workspace, api.RootArtifacts) {
	t.Helper()
	modulePath := requireSoftHSM2(t)

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\nobjectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	const rootLabel, rootPIN = "api-test-root-token", "111111"
	const interLabel, interPIN = "api-test-intermediate-token", "123456"
	for _, tok := range []struct{ label, pin string }{{rootLabel, rootPIN}, {interLabel, interPIN}} {
		cmd := exec.Command("softhsm2-util", "--init-token", "--free",
			"--label", tok.label, "--so-pin", "000000", "--pin", tok.pin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("softhsm2-util --init-token (%s): %v: %s", tok.label, err, out)
		}
	}

	adapter, err := pk11.NewSoftHSM2Adapter(modulePath)
	if err != nil {
		t.Fatalf("NewSoftHSM2Adapter: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })

	ctx := context.Background()
	wss, err := adapter.Workspaces(ctx)
	if err != nil {
		t.Fatalf("Workspaces: %v", err)
	}
	byLabel := map[string]pk11.Workspace{}
	for _, w := range wss {
		byLabel[w.Label] = w
	}
	rootWS, ok := byLabel[rootLabel]
	if !ok {
		t.Fatalf("workspace %q not found among %+v", rootLabel, wss)
	}
	interWS, ok := byLabel[interLabel]
	if !ok {
		t.Fatalf("workspace %q not found among %+v", interLabel, wss)
	}

	const interKeyLabel = "api-test-intermediate-key-v1"
	result, err := ca.RunCeremony(ctx, adapter, pk11.SessionOptions{}, ca.CeremonyParams{
		RootWorkspace: rootWS,
		RootPIN:       func() ([]byte, error) { return []byte(rootPIN), nil },
		RootKeyLabel:  "api-test-root-key-v1",
		RootSubject:   pkix.Name{CommonName: "hsm-pki-platform api test Root CA"},
		RootCurve:     pk11.P256,
		RootCRLURL:    "http://pki.example.test/root.crl",
		RootCertURL:   "http://pki.example.test/root.crt",

		IntermediateWorkspace: interWS,
		IntermediatePIN:       func() ([]byte, error) { return []byte(interPIN), nil },
		IntermediateKeyLabel:  interKeyLabel,
		IntermediateSubject:   pkix.Name{CommonName: "hsm-pki-platform api test Intermediate CA"},
		IntermediateCurve:     pk11.P256,
	})
	if err != nil {
		t.Fatalf("RunCeremony: %v", err)
	}

	interCertPath := filepath.Join(dir, "intermediate.pem")
	if err := os.WriteFile(interCertPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.IntermediateCertDER}), 0644); err != nil {
		t.Fatalf("WriteFile(intermediate): %v", err)
	}

	// Load it exactly the way cmd/hsm-pki-server does, so these tests
	// exercise the real startup path rather than a shortcut around it.
	resolvePIN := func() ([]byte, error) { return []byte(interPIN), nil }
	c, err := ca.LoadIntermediate(ctx, adapter, interWS, pk11.SessionOptions{}, resolvePIN, ca.LoadIntermediateParams{
		KeyLabel: interKeyLabel,
		CertPath: interCertPath,
		Curve:    pk11.P256,
		CertTTL:  time.Hour,
	})
	if err != nil {
		t.Fatalf("LoadIntermediate: %v", err)
	}

	root := api.RootArtifacts{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.RootCertDER}),
		CRLPEM:  pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: result.RootCRLDER}),
	}
	return c, adapter, interWS, root
}
