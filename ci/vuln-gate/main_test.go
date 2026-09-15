package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A fixed clock, so no test starts failing on a date.
var testNow = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func writeAllowlist(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vuln-allowlist.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing allowlist: %v", err)
	}
	return path
}

// govulncheck's real output shape, captured from v1.7.0 against
// golang.org/x/text v0.3.0, so a format change shows up here.
const gvcCalled = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
{"osv":{"id":"GO-2021-0113","aliases":["CVE-2021-38561","GHSA-ppp9-7jff-5vj2"],"summary":"Out-of-bounds read in golang.org/x/text/language"}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.0"}]}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.0","package":"golang.org/x/text/language"}]}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.0","package":"golang.org/x/text/language","function":"Parse"}]}}
`

const gvcClean = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
`

// govulncheck in JSON mode exits 0 on a called vulnerability, so the
// verdict comes from the content.
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
	// The two shallower findings are reported as context, not blockers.
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

// govulncheck names this GO-2021-0113; a reviewer writes down the CVE.
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
	// The log says the entry expired.
	if !strings.Contains(out.String(), "EXPIRED CVE-2021-38561") {
		t.Fatalf("expiry was not reported:\n%s", out.String())
	}
}

// trivy accepts an entry with no expiry and suppresses forever (measured
// against trivy 0.67.0).
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

// Two entries for one id: position would choose between them.
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

// A misspelled key must not read as an absent one; expires_at ignored
// would be a never-expiring entry.
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

// Empty input and a clean scan have the same exit status in JSON mode.
func TestTruncatedGovulncheckOutputIsRefused(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-allowlist", writeAllowlist(t, "vulnerabilities: []\n"), "-govulncheck", "-"},
		strings.NewReader(""), &out, testNow)
	if err == nil || !strings.Contains(err.Error(), "did not run to completion") {
		t.Fatalf("error = %v, want one refusing empty govulncheck output", err)
	}
}

// A repository with no accepted findings needs no file.
func TestMissingAllowlistIsNotAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	var out bytes.Buffer
	if err := run([]string{"-allowlist", missing, "-govulncheck", "-"},
		strings.NewReader(gvcClean), &out, testNow); err != nil {
		t.Fatalf("a missing allowlist was treated as a failure: %v", err)
	}
}

// The file this repository ships must satisfy its own validator.
func TestRepositoryAllowlistIsValid(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-allowlist", filepath.Join("..", "vuln-allowlist.yaml")},
		strings.NewReader(""), &out, time.Now()); err != nil {
		t.Fatalf("ci/vuln-allowlist.yaml does not satisfy its own validator: %v", err)
	}
}

// --- what each scanner reports about the allowlist ------------------------

// trivy's real --show-suppressed shape, captured from 0.74.0 against this
// repository's service image, so a format change shows up here rather
// than as an allowlist entry silently reading as unused.
const trivySuppressed = `{
  "SchemaVersion": 2,
  "Trivy": {"Version": "0.74.0"},
  "Results": [
    {
      "Target": "hsm-pki-server:ci (debian 12.15)",
      "ExperimentalModifiedFindings": [
        {
          "Type": "vulnerability",
          "Status": "ignored",
          "Statement": "accepted while the fix is unreleased",
          "Source": "/vuln-allowlist.yaml",
          "Finding": {"VulnerabilityID": "CVE-2026-18374"}
        },
        {
          "Type": "vulnerability",
          "Status": "ignored",
          "Statement": "from somewhere that is not this allowlist",
          "Source": "/other.yaml",
          "Finding": {"VulnerabilityID": "CVE-2000-11111"}
        }
      ]
    }
  ]
}`

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

const oneUsedOneStale = `vulnerabilities:
  - id: CVE-2026-18374
    statement: accepted while the fix is unreleased
    expired_at: 2026-11-01
  - id: CVE-9999-00000
    statement: matches nothing any more
    expired_at: 2026-11-01
`

// A hits file records what one scanner used, and only ids the allowlist
// actually carries: a suppression from another source is not this file's
// business.
func TestTrivyReportRecordsOnlyAllowlistedSuppressions(t *testing.T) {
	hits := filepath.Join(t.TempDir(), "hits.json")
	var out bytes.Buffer
	err := run([]string{
		"-allowlist", writeAllowlist(t, oneUsedOneStale),
		"-trivy", writeFile(t, "trivy.json", trivySuppressed),
		"-write-hits", hits, "-scanner", "trivy-image",
	}, strings.NewReader(""), &out, testNow)
	if err != nil {
		t.Fatalf("reading a trivy report failed: %v\n%s", err, out.String())
	}
	body, rerr := os.ReadFile(hits)
	if rerr != nil {
		t.Fatalf("reading hits: %v", rerr)
	}
	got := string(body)
	if !strings.Contains(got, `"scanner": "trivy-image"`) {
		t.Fatalf("hits file does not name the scanner:\n%s", got)
	}
	if !strings.Contains(got, "CVE-2026-18374") {
		t.Fatalf("hits file does not record the entry trivy used:\n%s", got)
	}
	if strings.Contains(got, "CVE-2000-11111") {
		t.Fatalf("hits file records a suppression this allowlist did not make:\n%s", got)
	}
}

// The union, not any one scanner: an entry may cover a finding only one of
// them can see, so a per-scanner check would fail on a correct entry.
func TestEntryUsedByOneScannerIsNotUnused(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{
		"-allowlist", writeAllowlist(t, oneUsedOneStale),
		"-require-used", writeFile(t, "a.json", `{"scanner":"govulncheck","matched":[]}`),
		"-require-used", writeFile(t, "b.json", `{"scanner":"trivy-image","matched":["CVE-2026-18374"]}`),
	}, strings.NewReader(""), &out, testNow)
	if err == nil {
		t.Fatal("the stale entry did not fail the check")
	}
	if !strings.Contains(out.String(), "UNUSED  CVE-9999-00000") {
		t.Fatalf("output does not name the unused entry:\n%s", out.String())
	}
	if strings.Contains(out.String(), "UNUSED  CVE-2026-18374") {
		t.Fatalf("an entry used by one scanner was reported unused:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "in use  CVE-2026-18374 (matched by trivy-image)") {
		t.Fatalf("output does not say which scanner used the entry:\n%s", out.String())
	}
}

func TestEveryEntryUsedPasses(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{
		"-allowlist", writeAllowlist(t, oneUsedOneStale),
		"-require-used", writeFile(t, "a.json", `{"scanner":"govulncheck","matched":["CVE-9999-00000"]}`),
		"-require-used", writeFile(t, "b.json", `{"scanner":"trivy-fs","matched":["CVE-2026-18374"]}`),
	}, strings.NewReader(""), &out, testNow)
	if err != nil {
		t.Fatalf("every entry was used and the check still failed: %v\n%s", err, out.String())
	}
}

// An expired entry has already stopped suppressing, so requiring it to
// have suppressed something would report the same fact twice and as the
// wrong kind of problem.
func TestExpiredEntryIsNotRequiredToBeUsed(t *testing.T) {
	const expired = `vulnerabilities:
  - id: CVE-2026-18374
    statement: left in place past its expiry
    expired_at: 2026-08-01
`
	var out bytes.Buffer
	err := run([]string{
		"-allowlist", writeAllowlist(t, expired),
		"-require-used", writeFile(t, "a.json", `{"scanner":"govulncheck","matched":[]}`),
	}, strings.NewReader(""), &out, testNow)
	if err != nil {
		t.Fatalf("an expired entry was reported as unused: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "EXPIRED CVE-2026-18374") {
		t.Fatalf("the expiry itself went unreported:\n%s", out.String())
	}
}

// A hits file with no scanner name is almost always the wrong file, and
// its contents cannot be reported usefully either way.
func TestUnnamedHitsFileIsRefused(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{
		"-allowlist", writeAllowlist(t, "vulnerabilities: []\n"),
		"-require-used", writeFile(t, "a.json", `{"matched":[]}`),
	}, strings.NewReader(""), &out, testNow)
	if err == nil {
		t.Fatal("a hits file naming no scanner was accepted")
	}
	if !strings.Contains(err.Error(), "names no scanner") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
