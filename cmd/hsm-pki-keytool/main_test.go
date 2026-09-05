package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/LockedWayi/hsm-pki-platform/internal/hsmtest"
)

func requireSoftHSM2(t *testing.T) string {
	t.Helper()
	return hsmtest.RequireSoftHSM2(t)
}

// initTwoTokens exposes the backend's two tokens to a CLI test: it puts the
// PINs into environment variables, because the command takes the *name* of
// the variable rather than a PIN value, and hands back the
// labels the flags need.
//
// It used to provision SoftHSM2 tokens inline, which is why every ceremony
// CLI test ran against one vendor. The tokens now come from
// internal/hsmtest, so these run wherever the environment provides a
// backend.
func initTwoTokens(t *testing.T, b *hsmtest.Backend) (rootPINEnv, interPINEnv string) {
	t.Helper()
	rootPINEnv, interPINEnv = "KEYTOOL_TEST_ROOT_PIN", "KEYTOOL_TEST_INTER_PIN"
	t.Setenv(rootPINEnv, b.SecondaryPIN)
	t.Setenv(interPINEnv, b.PrimaryPIN)
	return rootPINEnv, interPINEnv
}

// ceremonyArgs builds a complete, valid flag set, so each test can mutate
// exactly the one thing it is about.
//
// The key labels are run-scoped. A vendor whose tokens persist between runs
// would otherwise hit the ceremony's own "refuses to overwrite an existing
// key label" guard on the second run — which is the guard working, not a
// test failure, but it makes the suite unrepeatable.
func ceremonyArgs(t *testing.T, b *hsmtest.Backend, dir string) []string {
	t.Helper()
	rootPINEnv, interPINEnv := initTwoTokens(t, b)
	// The command under test builds its own adapter over the same module,
	// and ProtectToolkit refuses a second C_Initialize in one process. The
	// harness's adapter has already resolved the token labels above, so it
	// has nothing left to do — hand the module over.
	b.Release()
	return []string{
		"-adapter", b.AdapterName,
		"-module", b.ModulePath,
		"-root-workspace", b.Secondary.Label,
		"-root-pin-env", rootPINEnv,
		"-root-key-label", b.Label("cli-root-key-v1"),
		"-root-cert-out", filepath.Join(dir, "root.pem"),
		"-root-crl-out", filepath.Join(dir, "root-crl.pem"),
		"-root-crl-url", "http://pki.example.test/root.crl",
		"-root-cert-url", "http://pki.example.test/root.crt",
		"-intermediate-workspace", b.Primary.Label,
		"-intermediate-pin-env", interPINEnv,
		"-intermediate-key-label", b.Label("cli-inter-key-v1"),
		"-intermediate-cert-out", filepath.Join(dir, "intermediate.pem"),
	}
}

func TestRunCeremonyCmd_ProducesArtifacts(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		dir := t.TempDir()

		if err := runCeremonyCmd(ceremonyArgs(t, b, dir)); err != nil {
			t.Fatalf("runCeremonyCmd: %v", err)
		}

		for _, name := range []string{"root.pem", "intermediate.pem", "root-crl.pem"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatalf("expected artifact %s to exist: %v", name, err)
			}
		}
	})
}

// TestRunCeremonyCmd_RequiresDistributionURLs pins that the ceremony cannot
// be run without deciding where the root CRL and certificate will live.
// These become extensions on a certificate that can never be re-signed
// without bringing the offline root back out, so the decision has to happen
// before the signature, not after.
func TestRunCeremonyCmd_RequiresDistributionURLs(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {

		for _, missing := range []string{"-root-crl-url", "-root-cert-url"} {
			t.Run(missing, func(t *testing.T) {
				dir := t.TempDir()
				args := ceremonyArgs(t, b, dir)
				for i, a := range args {
					if a == missing {
						args[i+1] = ""
					}
				}
				if err := runCeremonyCmd(args); err == nil {
					t.Fatalf("runCeremonyCmd without %s succeeded, want an error", missing)
				}
			})
		}
	})
}

func TestRunCeremonyCmd_RefusesToOverwriteExistingOutput(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		dir := t.TempDir()

		if err := os.WriteFile(filepath.Join(dir, "root.pem"), []byte("pre-existing"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		if err := runCeremonyCmd(ceremonyArgs(t, b, dir)); err == nil {
			t.Fatal("runCeremonyCmd with a pre-existing output file succeeded, want an error")
		}
	})
}

// TestFindWorkspace_AmbiguousLabelFailsClosed covers the case PKCS#11
// explicitly permits and this tool must not resolve by guessing: two
// distinct tokens carrying the same label.
func TestFindWorkspace_AmbiguousLabelFailsClosed(t *testing.T) {
	modulePath := requireSoftHSM2(t)
	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	if err := os.WriteFile(confPath, []byte("directories.tokendir = "+tokenDir+"\nobjectstore.backend = file\nlog.level = ERROR\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	// Two tokens, deliberately sharing one label.
	for i := 0; i < 2; i++ {
		cmd := exec.Command("softhsm2-util", "--init-token", "--free",
			"--label", "duplicate-label", "--so-pin", "000000", "--pin", "123456")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("softhsm2-util --init-token (%d): %v: %s", i, err, out)
		}
	}

	adapter, err := newVendorAdapter("softhsm2", modulePath)
	if err != nil {
		t.Fatalf("newVendorAdapter: %v", err)
	}
	defer adapter.Close()
	ctx := context.Background()

	if _, err := findWorkspace(ctx, adapter, "duplicate-label", ""); err == nil {
		t.Fatal("findWorkspace resolved an ambiguous label instead of failing closed")
	}

	// With a serial supplied, the ambiguity is resolved and the lookup must
	// return that exact token.
	wss, err := adapter.Workspaces(ctx)
	if err != nil {
		t.Fatalf("Workspaces: %v", err)
	}
	var target string
	for _, w := range wss {
		if w.Label == "duplicate-label" {
			target = w.Serial
			break
		}
	}
	if target == "" {
		t.Fatal("no token with the duplicate label was enumerated")
	}
	got, err := findWorkspace(ctx, adapter, "duplicate-label", target)
	if err != nil {
		t.Fatalf("findWorkspace with a disambiguating serial: %v", err)
	}
	if got.Serial != target {
		t.Fatalf("findWorkspace returned serial %q, want %q", got.Serial, target)
	}
}

func TestRunCeremonyCmd_MissingRequiredFlag(t *testing.T) {
	err := runCeremonyCmd([]string{"-module", "/dev/null"})
	if err == nil {
		t.Fatal("runCeremonyCmd with no flags set succeeded, want an error")
	}
}

func TestRunCeremonyCmd_UnknownWorkspaceFailsClosed(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		dir := t.TempDir()

		args := ceremonyArgs(t, b, dir)
		for i, a := range args {
			if a == "-root-workspace" {
				args[i+1] = "does-not-exist"
			}
		}
		if err := runCeremonyCmd(args); err == nil {
			t.Fatal("runCeremonyCmd against an unknown workspace label succeeded, want an error")
		}
	})
}

func TestRun_UnknownCommand(t *testing.T) {
	if err := run([]string{"not-a-real-command"}); err == nil {
		t.Fatal("run with an unknown command succeeded, want an error")
	}
}

func TestRun_NoArgs(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("run with no arguments succeeded, want an error")
	}
}

func TestNewVendorAdapter_UnknownAdapter(t *testing.T) {
	if _, err := newVendorAdapter("not-a-real-adapter", "/dev/null"); err == nil {
		t.Fatal("newVendorAdapter with an unknown adapter name succeeded, want an error")
	}
}

func TestPINResolver_UnsetEnvVar(t *testing.T) {
	resolve := pinResolver("KEYTOOL_TEST_DEFINITELY_UNSET_VAR")
	if _, err := resolve(); err == nil {
		t.Fatal("pinResolver for an unset environment variable succeeded, want an error")
	}
}

func TestWriteCertPEM_And_WriteCRLPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	crlPath := filepath.Join(dir, "crl.pem")

	if err := writeCertPEM(certPath, []byte("not real DER, just needs bytes")); err != nil {
		t.Fatalf("writeCertPEM: %v", err)
	}
	if err := writeCRLPEM(crlPath, []byte("not real DER, just needs bytes")); err != nil {
		t.Fatalf("writeCRLPEM: %v", err)
	}
	for _, path := range []string{certPath, crlPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}
}
