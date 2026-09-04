package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The gate is exercised against the same real cosign signature the
// artifactsig package uses -- a bundle produced over the HSM, not one this
// test made. What is checked here is the *command*: that its exit path is
// non-nil error for every way verification can fail, since exit status is
// the whole interface a packaging step reads (CLAUDE.md §3.4).

const (
	fixtureDir   = "../../internal/artifactsig/testdata"
	publishedKey = "../../docs/keys/artifact-signing-key-v1.pub"
	otherKey     = "../../docs/keys/image-signing-key-v1.pub"
)

func artifact() string { return filepath.Join(fixtureDir, "sample-artifact.txt") }
func bundle() string   { return filepath.Join(fixtureDir, "sample-artifact.bundle") }

func TestRun_AcceptsAGenuineSignature(t *testing.T) {
	var out strings.Builder
	if err := run([]string{"-key", publishedKey, "-bundle", bundle(), artifact()}, &out); err != nil {
		t.Fatalf("a genuine signature was rejected: %v", err)
	}
	if !strings.Contains(out.String(), "verified:") {
		t.Fatalf("said nothing about verifying: %q", out.String())
	}
}

func TestRun_RefusesEveryWayVerificationCanFail(t *testing.T) {
	corrupted := filepath.Join(t.TempDir(), "corrupted.txt")
	original, err := os.ReadFile(artifact())
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	tampered := append([]byte(nil), original...)
	tampered[0] ^= 0x01
	if err := os.WriteFile(corrupted, tampered, 0o600); err != nil {
		t.Fatalf("writing corrupted artifact: %v", err)
	}

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"a single flipped bit", []string{"-key", publishedKey, "-bundle", bundle(), corrupted}, "different artifact"},
		{"the other purpose's key", []string{"-key", otherKey, "-bundle", bundle(), artifact()}, "names key"},
		{"no key given", []string{"-bundle", bundle(), artifact()}, "need -key"},
		{"no bundle given", []string{"-key", publishedKey, artifact()}, "need -key"},
		{"no artifact given", []string{"-key", publishedKey, "-bundle", bundle()}, "need -key"},
		{"two artifacts given", []string{"-key", publishedKey, "-bundle", bundle(), artifact(), artifact()}, "need -key"},
		{"a key that is not there", []string{"-key", "/nonexistent.pub", "-bundle", bundle(), artifact()}, "reading public key"},
		{"a bundle that is not there", []string{"-key", publishedKey, "-bundle", "/nonexistent.bundle", artifact()}, "reading bundle"},
		{"an artifact that is not there", []string{"-key", publishedKey, "-bundle", bundle(), "/nonexistent"}, "opening artifact"},
		{"a bundle that is not a bundle", []string{"-key", publishedKey, "-bundle", publishedKey, artifact()}, "parsing bundle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.args, io.Discard)
			if err == nil {
				t.Fatal("the gate passed")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong reason: got %v, want something containing %q", err, tc.want)
			}
		})
	}
}
