package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A fixed clock. Every expiry assertion in this file is relative to it, so
// none of these tests start failing on a date nobody chose.
var testNow = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func writeAllowlist(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vuln-allowlist.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing allowlist: %v", err)
	}
	return path
}

// govulncheck's real output shape, trimmed to what the gate reads. Captured
// from govulncheck v1.7.0 against golang.org/x/text v0.3.0 rather than
// invented, so a change in that format shows up as a test failure here
// instead of as a gate that silently stops finding anything.
const gvcCalled = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
{"osv":{"id":"GO-2021-0113","aliases":["CVE-2021-38561","GHSA-ppp9-7jff-5vj2"],"summary":"Out-of-bounds read in golang.org/x/text/language"}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.0"}]}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.0","package":"golang.org/x/text/language"}]}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.0","package":"golang.org/x/text/language","function":"Parse"}]}}
`

const gvcClean = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
`

// The gate's reason for existing: govulncheck in JSON mode exits 0 on a
// called vulnerability, so the verdict has to come from the content.
func TestReachableVulnerabilityBlocks(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-allowlist", writeAllowlist(t, "vulnerabilities: []\n"), "-govulncheck", "-"},
		strings.NewReader(gvcCalled), &out, testNow)
	if err == nil {
		t.Fatal("a called vulnerability with no exception did not block")
	}
	if !strings.Contains(out.String(), "BLOCKING: GO-2021-0113") {
		t.Fatalf("output does not name the blocking vulnerability:\n%s", out.String())
	}
	// The two shallower findings for the same vulnerability must be
	// reported as context, never as blockers — otherwise the gate is just
	// trivy with extra steps.
	if !strings.Contains(out.String(), "imported, not called") {
		t.Fatalf("output does not distinguish the unreachable findings:\n%s", out.String())
	}
}

func TestCleanScanPasses(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-allowlist", writeAllowlist(t, "vulnerabilities: []\n"), "-govulncheck", "-"},
		strings.NewReader(gvcClean), &out, testNow); err != nil {
		t.Fatalf("clean scan blocked: %v\n%s", err, out.String())
	}
}

// The single-allowlist claim: govulncheck names this GO-2021-0113, a human
// reviewing it writes down the CVE. One file has to serve both.
func TestAllowlistSuppressesByCVEAlias(t *testing.T) {
	list := writeAllowlist(t, `vulnerabilities:
  - id: CVE-2021-38561
    statement: accepted for the drill
    expired_at: 2026-10-01
`)
	var out bytes.Buffer
	if err := run([]string{"-allowlist", list, "-govulncheck", "-"},
		strings.NewReader(gvcCalled), &out, testNow); err != nil {
		t.Fatalf("an allowlisted CVE alias still blocked: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "accepted until 2026-10-01") {
		t.Fatalf("suppression is not visible in the output:\n%s", out.String())
	}
}

// An exception has to stop working on its own, or it is not an exception.
func TestExpiredEntryStopsSuppressing(t *testing.T) {
	list := writeAllowlist(t, `vulnerabilities:
  - id: CVE-2021-38561
    statement: accepted, then not
    expired_at: 2026-09-04
`)
	var out bytes.Buffer
	err := run([]string{"-allowlist", list, "-govulncheck", "-"},
		strings.NewReader(gvcCalled), &out, testNow)
	if err == nil {
		t.Fatal("an entry that expired yesterday still suppressed its finding")
	}
	// And the log has to say the entry expired, or the finding's return
	// looks like a new vulnerability appearing from nowhere.
	if !strings.Contains(out.String(), "EXPIRED CVE-2021-38561") {
		t.Fatalf("expiry was not reported:\n%s", out.String())
	}
}

// The defect trivy cannot catch, because trivy accepts it: an entry with no
// expiry date suppresses forever (measured against trivy 0.67.0).
func TestEntryWithoutExpiryIsRefused(t *testing.T) {
	list := writeAllowlist(t, `vulnerabilities:
  - id: CVE-2021-38561
    statement: forever, please
`)
	var out bytes.Buffer
	err := run([]string{"-allowlist", list}, strings.NewReader(""), &out, testNow)
	if err == nil {
		t.Fatal("an allowlist entry with no expiry was accepted")
	}
	if !strings.Contains(err.Error(), "no expired_at") {
		t.Fatalf("error does not name the missing expiry: %v", err)
	}
}

func TestEntryWithoutStatementIsRefused(t *testing.T) {
	list := writeAllowlist(t, `vulnerabilities:
  - id: CVE-2021-38561
    expired_at: 2026-10-01
`)
	err := run([]string{"-allowlist", list}, strings.NewReader(""), &bytes.Buffer{}, testNow)
	if err == nil || !strings.Contains(err.Error(), "no statement") {
		t.Fatalf("error = %v, want one naming the missing statement", err)
	}
}

// An expiry far enough out is a permanent exception wearing a date.
func TestExpiryBeyondTheHorizonIsRefused(t *testing.T) {
	list := writeAllowlist(t, `vulnerabilities:
  - id: CVE-2021-38561
    statement: technically has a date
    expired_at: 2099-01-01
`)
	err := run([]string{"-allowlist", list}, strings.NewReader(""), &bytes.Buffer{}, testNow)
	if err == nil || !strings.Contains(err.Error(), "not an expiry") {
		t.Fatalf("error = %v, want one rejecting the distant expiry", err)
	}
}

// Two decisions on file for one vulnerability means the one that applies is
// picked by position in the file, which is nobody's decision.
func TestDuplicateEntryIsRefused(t *testing.T) {
	list := writeAllowlist(t, `vulnerabilities:
  - id: CVE-2021-38561
    statement: first opinion
    expired_at: 2026-10-01
  - id: CVE-2021-38561
    statement: second opinion
    expired_at: 2026-11-01
`)
	err := run([]string{"-allowlist", list}, strings.NewReader(""), &bytes.Buffer{}, testNow)
	if err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Fatalf("error = %v, want one rejecting the duplicate", err)
	}
}

// A misspelled key must not read as an absent one: `expires_at` silently
// ignored would produce exactly the never-expiring entry this file forbids.
func TestUnknownFieldIsRefused(t *testing.T) {
	list := writeAllowlist(t, `vulnerabilities:
  - id: CVE-2021-38561
    statement: typo below
    expires_at: 2026-10-01
`)
	err := run([]string{"-allowlist", list}, strings.NewReader(""), &bytes.Buffer{}, testNow)
	if err == nil || !strings.Contains(err.Error(), "parsing allowlist") {
		t.Fatalf("error = %v, want one rejecting the unknown field", err)
	}
}

// Empty input and a clean scan are the same exit status in JSON mode, so
// the gate must be able to tell them apart from the content alone.
func TestTruncatedGovulncheckOutputIsRefused(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-allowlist", writeAllowlist(t, "vulnerabilities: []\n"), "-govulncheck", "-"},
		strings.NewReader(""), &out, testNow)
	if err == nil || !strings.Contains(err.Error(), "did not run to completion") {
		t.Fatalf("error = %v, want one refusing empty govulncheck output", err)
	}
}

// No accepted findings is the honest state of a clean repository, and it
// must not need a file to say so.
func TestMissingAllowlistIsNotAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	var out bytes.Buffer
	if err := run([]string{"-allowlist", missing, "-govulncheck", "-"},
		strings.NewReader(gvcClean), &out, testNow); err != nil {
		t.Fatalf("a missing allowlist was treated as a failure: %v", err)
	}
}

// The file this repository actually ships has to satisfy its own validator,
// or the gate is green only because nobody has run it against the real one.
func TestRepositoryAllowlistIsValid(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-allowlist", filepath.Join("..", "vuln-allowlist.yaml")},
		strings.NewReader(""), &out, time.Now()); err != nil {
		t.Fatalf("ci/vuln-allowlist.yaml does not satisfy its own validator: %v", err)
	}
}
