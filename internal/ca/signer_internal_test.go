package ca

// A white-box (package ca, not ca_test) test file, for the one thing this
// package's black-box tests structurally cannot reach: forcing a session
// to already be expired by the time Sign uses it. NewSigner itself opens a
// session with whatever SessionOptions it is given, so constructing a
// Signer with an already-expired budget fails during construction, before
// Sign is ever reached — there is no way to reproduce "the session Sign
// opens turns out to be expired" from outside the package without either a
// real sleep racing a timeout (flaky) or reaching into the unexported
// sessionOpts field this way (deterministic).

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

func requireSoftHSM2Internal(t *testing.T) string {
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

// TestSigner_Sign_ExpiredSessionFailsClosed covers Phase 2 sub-task 2.7's
// session-expiry failure path: a Sign call whose freshly opened session has
// already exceeded its budget by the time Login touches it must fail
// closed with an error identifiable as a session-expiry failure, never
// hang or panic.
func TestSigner_Sign_ExpiredSessionFailsClosed(t *testing.T) {
	modulePath := requireSoftHSM2Internal(t)

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

	const label, pin = "expiry-test-token", "123456"
	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", label, "--so-pin", "000000", "--pin", pin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("softhsm2-util --init-token: %v: %s", err, out)
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
	var ws pk11.Workspace
	for _, w := range wss {
		if w.Label == label {
			ws = w
		}
	}
	if ws.Label == "" {
		t.Fatalf("workspace %q not found among %+v", label, wss)
	}
	// Establish the anchor login once, exactly as Bootstrap does.
	if err := adapter.LoginToken(ctx, ws, []byte(pin), pk11.RoleUser); err != nil {
		t.Fatalf("LoginToken: %v", err)
	}

	const keyLabel = "expiry-test-key"
	if _, err := withSession(ctx, adapter, ws, pk11.SessionOptions{}, func(s *pk11.Session) (struct{}, error) {
		_, err := adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: keyLabel, Sign: true, Verify: true,
		})
		return struct{}{}, err
	}); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Built with a normal budget, so construction (which opens its own
	// session to read the public key) succeeds.
	signer, err := NewSigner(ctx, adapter, ws, pk11.SessionOptions{}, keyLabel, pk11.P256)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	// Force every subsequent session Sign opens to already be past budget.
	signer.sessionOpts = pk11.SessionOptions{IdleTimeout: time.Nanosecond, MaxTTL: time.Nanosecond}

	digest := sha256.Sum256([]byte("hsm-pki-platform phase 2 session-expiry test"))
	_, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil {
		t.Fatal("Sign with an already-expired session budget succeeded, want an error")
	}
	if !errors.Is(err, pk11.ErrSessionExpired) {
		t.Fatalf("Sign error = %v, want it to wrap pkcs11.ErrSessionExpired", err)
	}
}
