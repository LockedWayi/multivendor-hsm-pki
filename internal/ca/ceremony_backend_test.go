package ca_test

// Backend scaffolding for the ceremony suite.
//
// Every ceremony test runs against every backend the environment provides,
// following the same pattern as internal/pkcs11's conformance suite and for
// the same reason: the two-token root/intermediate layout is exactly the
// kind of design where a second vendor is likely to diverge, and an
// abstraction exercised against one implementation is a guess (CLAUDE.md §1,
// docs/phases/phase-3b-pki-hardening.md sub-task 3b.0).
//
// SoftHSM2 provisions two throwaway tokens per run and carries CI.
// ProtectServer runs against the maintainer's own two pre-provisioned
// tokens and is exercised only when the PROTECTSERVER_* variables are set;
// with them unset its subtests skip and the suite stays honestly green
// (CLAUDE.md §2.3 — nothing ProtectServer-only is ever reported as
// CI-verified).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// ceremonyBackend is one vendor's adapter plus the two tokens and PINs a
// ceremony needs.
//
// runID is folded into every key label a run creates. It is not cosmetic:
// ProtectServer's tokens persist on disk between runs, so a fixed label
// would make the second run of any test collide with the first run's keys
// and trip the ceremony's own "refuses to overwrite an existing key label"
// guard. SoftHSM2 gets fresh tokens every run and would not need it, but
// keeping both paths identical costs nothing and stops the two from
// drifting apart.
type ceremonyBackend struct {
	name              string
	adapter           pk11.VendorAdapter
	rootWS, interWS   pk11.Workspace
	rootPIN, interPIN string
	runID             string
}

func (b *ceremonyBackend) label(suffix string) string {
	return fmt.Sprintf("cer-%s-%s", b.runID, suffix)
}

func (b *ceremonyBackend) rootKeyLabel() string  { return b.label("root-key-v1") }
func (b *ceremonyBackend) interKeyLabel() string { return b.label("inter-key-v1") }

// forEachCeremonyBackend runs fn against every available backend as its own
// subtest. Each subtest builds a fresh backend — and therefore a fresh
// adapter — because a PKCS#11 module permits only one C_Initialize per
// process: two adapters over the same .so alive at once fails
// CKR_CRYPTOKI_ALREADY_INITIALIZED. Subtests run sequentially and each
// adapter is closed by its own cleanup, so only one is ever live.
func forEachCeremonyBackend(t *testing.T, fn func(t *testing.T, b *ceremonyBackend)) {
	t.Helper()
	backends := []struct {
		name  string
		setup func(t *testing.T) *ceremonyBackend
	}{
		{"SoftHSM2", setupSoftHSM2CeremonyBackend},
		{"ProtectServer", setupProtectServerCeremonyBackend},
	}
	for _, be := range backends {
		be := be
		t.Run(be.name, func(t *testing.T) {
			fn(t, be.setup(t))
		})
	}
}

// setupSoftHSM2CeremonyBackend provisions two independent, throwaway
// SoftHSM2 tokens under one module instance. No anchor login is
// established: RunCeremony owns login and logout of both tokens itself, and
// refuses to run if it finds a token already authenticated.
func setupSoftHSM2CeremonyBackend(t *testing.T) *ceremonyBackend {
	t.Helper()
	modulePath := requireSoftHSM2(t)

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\n" +
		"objectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	const rootLabel, rootPIN = "ceremony-root-token", "111111"
	const interLabel, interPIN = "ceremony-intermediate-token", "222222"
	for _, tok := range []struct{ label, pin string }{
		{rootLabel, rootPIN},
		{interLabel, interPIN},
	} {
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

	rootWS := mustFindWorkspace(t, adapter, rootLabel)
	interWS := mustFindWorkspace(t, adapter, interLabel)

	return &ceremonyBackend{
		name:    "SoftHSM2",
		adapter: adapter,
		rootWS:  rootWS, interWS: interWS,
		rootPIN: rootPIN, interPIN: interPIN,
		runID: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
}

// setupProtectServerCeremonyBackend wires the maintainer's own ProtectToolkit
// tokens in. Unlike SoftHSM2 it provisions nothing: the two user tokens are
// created once, by hand, with ctconf/ctkmu (docs/protectserver-setup.md), and
// this only looks them up.
func setupProtectServerCeremonyBackend(t *testing.T) *ceremonyBackend {
	t.Helper()
	modulePath := os.Getenv("PROTECTSERVER_MODULE")
	if modulePath == "" {
		t.Skip("PROTECTSERVER_MODULE not set — see docs/protectserver-setup.md; " +
			"this backend is maintainer-verified, never CI-verified (CLAUDE.md §2.3)")
	}

	rootLabel := os.Getenv("PROTECTSERVER_ROOT_WORKSPACE")
	interLabel := os.Getenv("PROTECTSERVER_INTERMEDIATE_WORKSPACE")
	rootPIN := os.Getenv("PROTECTSERVER_ROOT_PIN")
	interPIN := os.Getenv("PROTECTSERVER_INTERMEDIATE_PIN")
	if rootLabel == "" || interLabel == "" || rootPIN == "" || interPIN == "" {
		t.Skip("the two-token ceremony needs PROTECTSERVER_ROOT_WORKSPACE, " +
			"PROTECTSERVER_INTERMEDIATE_WORKSPACE, PROTECTSERVER_ROOT_PIN and " +
			"PROTECTSERVER_INTERMEDIATE_PIN — see docs/protectserver-setup.md")
	}
	if rootLabel == interLabel {
		t.Fatal("PROTECTSERVER_ROOT_WORKSPACE and PROTECTSERVER_INTERMEDIATE_WORKSPACE " +
			"name the same token; the ceremony requires two (phase-3b-pki-hardening.md)")
	}

	adapter, err := pk11.NewProtectServerAdapter(modulePath)
	if err != nil {
		t.Fatalf("NewProtectServerAdapter: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })

	return &ceremonyBackend{
		name:    "ProtectServer",
		adapter: adapter,
		rootWS:  mustFindWorkspace(t, adapter, rootLabel),
		interWS: mustFindWorkspace(t, adapter, interLabel),
		rootPIN: rootPIN, interPIN: interPIN,
		runID: fmt.Sprintf("%d", time.Now().UnixNano()),
	}
}

func mustFindWorkspace(t *testing.T, adapter pk11.VendorAdapter, label string) pk11.Workspace {
	t.Helper()
	wss, err := adapter.Workspaces(context.Background())
	if err != nil {
		t.Fatalf("Workspaces: %v", err)
	}
	for _, w := range wss {
		if w.Label == label {
			if w.Serial == "" {
				t.Fatalf("workspace %q carries no token serial; the ceremony's token-identity check needs one", label)
			}
			return w
		}
	}
	t.Fatalf("workspace %q not found among %+v", label, wss)
	return pk11.Workspace{}
}
