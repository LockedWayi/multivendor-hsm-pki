package ca

// A white-box test, for the one case the black-box tests cannot reach:
// a session that is already expired when Sign uses it. NewSigner opens a
// session with the options it is given, so an expired budget fails
// during construction. This test sets the unexported sessionOpts after
// construction, which is deterministic where a real sleep would be flaky.

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
		t.Skip("SoftHSM2 module not found; run inside the dev container (see CONTRIBUTING.md)")
	}
	return modulePath
}

// TestSigner_Sign_ExpiredSessionFailsClosed: a Sign call whose fresh
// session is already past its budget fails with a session-expiry error
// and never hangs.
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
	// The anchor login, once.
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

	// Built with a normal budget, so construction succeeds.
	signer, err := NewSigner(ctx, adapter, ws, pk11.SessionOptions{}, keyLabel, pk11.P256)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	// Every session Sign opens is now already past budget.
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
