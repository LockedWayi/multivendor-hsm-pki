package main

import (
	"strings"
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
)

// These touch no token. They cover the guards that run before anything is
// destroyed.

// TestRun_RefusesAnEmptyPrefix: an empty prefix matches every object on
// the token.
func TestRun_RefusesAnEmptyPrefix(t *testing.T) {
	t.Setenv("TOKEN_CLEANUP_TEST_PIN", "1234")
	err := run([]string{
		"-module", "/nonexistent/module.so",
		"-workspace", "some-token",
		"-pin-env", "TOKEN_CLEANUP_TEST_PIN",
		"-prefix", "",
		"-confirm",
	})
	if err == nil {
		t.Fatal("an empty -prefix was accepted; that matches every object on the token")
	}
	if !strings.Contains(err.Error(), "every object") {
		t.Fatalf("error = %v, want it to say why an empty prefix is refused", err)
	}
	// It must fail on the prefix, not on the unreachable module.
	if strings.Contains(err.Error(), "module") {
		t.Fatalf("failed for the wrong reason: %v", err)
	}
}

func TestRun_RequiresTheFlagsThatSayWhatToActOn(t *testing.T) {
	for _, missing := range []string{"-module", "-workspace", "-pin-env"} {
		t.Run(missing, func(t *testing.T) {
			args := map[string]string{
				"-module": "/nonexistent/module.so", "-workspace": "some-token", "-pin-env": "VAR",
			}
			delete(args, missing)
			var flat []string
			for k, v := range args {
				flat = append(flat, k, v)
			}
			err := run(flat)
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("run without %s = %v, want an error naming it", missing, err)
			}
		})
	}
}

// TestNewAdapter_KnowsEveryConfigAdapter: the cleanup tool must reach
// every backend the suite can leave objects on, so its -adapter switch
// accepts every name internal/config does. The module path does not
// exist; the failure must be the module's, never the name's.
func TestNewAdapter_KnowsEveryConfigAdapter(t *testing.T) {
	for _, adapter := range []string{config.AdapterSoftHSM2, config.AdapterProtectServer, config.AdapterLuna} {
		t.Run(adapter, func(t *testing.T) {
			_, err := newAdapter(adapter, "/nonexistent/module.so")
			if err == nil {
				t.Fatal("newAdapter loaded a module that does not exist")
			}
			if strings.Contains(err.Error(), "unknown -adapter") {
				t.Fatalf("-adapter %s is a name internal/config accepts and this tool does not: %v", adapter, err)
			}
		})
	}
	if _, err := newAdapter("quantum-hsm", "/nonexistent/module.so"); err == nil || !strings.Contains(err.Error(), "unknown -adapter") {
		t.Fatalf("an unknown -adapter must be refused by name, got %v", err)
	}
}
