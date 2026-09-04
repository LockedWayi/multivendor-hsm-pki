package main

import (
	"strings"
	"testing"
)

// These touch no token: they are about the guards that run *before* this
// tool is allowed to destroy anything, which is the part that must never
// regress. The destroying itself is exercised by the operator running it.

// TestRun_RefusesAnEmptyPrefix is the one that matters. An empty prefix
// matches every object on the token, so "clear this run's test keys" and
// "wipe the token" would be one missing flag apart — and the second is not
// undoable (CLAUDE.md §3.4, §3.9).
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
	// And it must fail on the prefix, not on the unreachable module —
	// otherwise the guard is being credited for an accident.
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
