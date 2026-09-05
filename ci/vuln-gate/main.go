// Command vuln-gate decides whether a dependency scan blocks the build, and
// is the only place an exception may be granted.
//
// # Why a tool sits between the scanners and the verdict
//
// Two measured properties of the scanners make "run it and check $?" the
// wrong gate, and each one fails open rather than closed.
//
//   - govulncheck with -format json exits 0 even when it finds a called
//     vulnerability. The exit code carries the verdict only in text mode,
//     and text mode cannot be filtered against an allowlist. A pipeline
//     that asks for JSON and trusts the exit status is a gate that never
//     fires (measured 2026-09-05 against golang.org/x/text v0.3.0: one
//     called vulnerability, exit status 0).
//
//   - trivy honours an ignore entry that carries no expiry date, forever.
//     An exception with no expiry is not an accepted risk, it is a
//     forgotten one, and the phase file asks for expiry dates precisely so
//     that accepting a finding costs something later. Trivy will not
//     enforce that; this does, over the same file trivy reads.
//
// So the allowlist is a single reviewed file in trivy's own ignorefile
// schema -- trivy consumes it directly, and this program both validates it
// and applies it to govulncheck, whose findings trivy never sees.
//
// # What each scanner is asked
//
// trivy fs answers "is a vulnerable version present at all", over the whole
// module graph. govulncheck answers the narrower and more expensive
// question, "does this code actually reach the vulnerable function". They
// disagree by design, and both answers are wanted: the first is what an
// auditor reads off go.mod, the second is what an attacker can use today.
//
// This gate therefore fails on a govulncheck finding only when the
// vulnerable symbol is *called*. Findings at the imported-but-not-called
// and required-but-not-imported levels are printed, because they are the
// list of things that become gate failures the moment somebody adds a call
// -- but they are trivy's question, and trivy is already blocking on them.
//
// Usage:
//
//	go run ./ci/vuln-gate                                  # validate the allowlist
//	govulncheck -format json ./... | go run ./ci/vuln-gate -govulncheck -
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "vuln-gate: %v\n", err)
		os.Exit(1)
	}
}

// expiryLayout is the date form trivy's ignorefile uses. Dates only: an
// exception whose expiry turns on the hour is precision nobody reviewing it
// will use.
const expiryLayout = "2006-01-02"

// run takes its clock and its streams explicitly. The whole behaviour of
// this gate turns on what "expired" means today, so a test that cannot move
// the clock could only ever check the paths that do not involve one.
func run(args []string, in io.Reader, out io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("vuln-gate", flag.ContinueOnError)
	fs.SetOutput(out)
	allowlistPath := fs.String("allowlist", "ci/vuln-allowlist.yaml", "path to the shared vulnerability allowlist")
	govulnPath := fs.String("govulncheck", "", "govulncheck -format json output to judge (\"-\" for stdin); omit to validate the allowlist only")
	maxHorizonDays := fs.Int("max-horizon-days", 180, "furthest future date an allowlist entry may expire on")
	if err := fs.Parse(args); err != nil {
		return err
	}

	allowlist, err := loadAllowlist(*allowlistPath, now, *maxHorizonDays)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "allowlist %s: %d entr%s, %d currently in force\n",
		*allowlistPath, len(allowlist.entries), plural(len(allowlist.entries)), allowlist.activeCount(now))
	for _, e := range allowlist.entries {
		if e.expired(now) {
			// Not an error: an expired entry simply stops suppressing, so
			// the finding it covered comes back on its own. Saying so here
			// is what stops that looking like a new vulnerability.
			fmt.Fprintf(out, "  EXPIRED %s (on %s) — no longer suppressed, remove it or re-review\n",
				e.ID, e.ExpiredAt)
		}
	}

	if *govulnPath == "" {
		return nil
	}

	src := in
	if *govulnPath != "-" {
		f, err := os.Open(*govulnPath)
		if err != nil {
			return fmt.Errorf("reading govulncheck output: %w", err)
		}
		defer f.Close()
		src = f
	}
	return judgeGovulncheck(src, out, allowlist, now)
}

// --- the allowlist -------------------------------------------------------

// allowEntry is one accepted finding. The field names and the file's shape
// are trivy's ignorefile schema, not an invention: trivy reads this same
// file directly, so a second format would mean two files to review and two
// chances for them to disagree.
type allowEntry struct {
	ID        string `yaml:"id"`
	Statement string `yaml:"statement"`
	ExpiredAt string `yaml:"expired_at"`

	expiry time.Time
}

func (e allowEntry) expired(now time.Time) bool { return !now.Before(e.expiry) }

type allowlistFile struct {
	Vulnerabilities []allowEntry `yaml:"vulnerabilities"`
}

type allowlist struct {
	entries []allowEntry
	byID    map[string]allowEntry
}

func (a *allowlist) activeCount(now time.Time) int {
	n := 0
	for _, e := range a.entries {
		if !e.expired(now) {
			n++
		}
	}
	return n
}

// covers reports whether any of the identifiers naming one vulnerability is
// allowlisted and still in force. Several identifiers are passed because
// govulncheck names a vulnerability by its GO- id while the allowlist is
// most often written against the CVE a human looked up; matching on either
// is what lets one file serve both scanners.
func (a *allowlist) covers(now time.Time, ids ...string) (allowEntry, bool) {
	for _, id := range ids {
		if e, ok := a.byID[id]; ok && !e.expired(now) {
			return e, true
		}
	}
	return allowEntry{}, false
}

// loadAllowlist reads and validates the file. Validation is fail-closed
// (CLAUDE.md §3.4): every defect below makes the gate refuse to run rather
// than run with an allowlist it does not fully understand, because the
// failure mode of a misread allowlist is a suppressed vulnerability.
//
// A missing file is not a defect. The honest state of a repository with no
// accepted findings is no allowlist at all, and requiring an empty file to
// exist would only teach people to create one before they need it.
func loadAllowlist(path string, now time.Time, maxHorizonDays int) (*allowlist, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &allowlist{byID: map[string]allowEntry{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading allowlist: %w", err)
	}

	var parsed allowlistFile
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a typo'd key must not read as an absent one
	if err := dec.Decode(&parsed); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing allowlist %s: %w", path, err)
	}

	horizon := now.AddDate(0, 0, maxHorizonDays)
	a := &allowlist{byID: make(map[string]allowEntry, len(parsed.Vulnerabilities))}
	var problems []string
	for i, e := range parsed.Vulnerabilities {
		where := fmt.Sprintf("entry %d", i+1)
		if e.ID != "" {
			where = e.ID
		}
		if e.ID == "" {
			problems = append(problems, fmt.Sprintf("%s: no id", where))
			continue
		}
		if strings.TrimSpace(e.Statement) == "" {
			problems = append(problems, fmt.Sprintf("%s: no statement — an exception nobody wrote a reason for cannot be reviewed", where))
		}
		if e.ExpiredAt == "" {
			// Trivy accepts this and suppresses forever; that is the whole
			// reason this validator exists.
			problems = append(problems, fmt.Sprintf("%s: no expired_at — an exception with no expiry is a forgotten risk, not an accepted one", where))
		} else {
			expiry, perr := time.Parse(expiryLayout, e.ExpiredAt)
			if perr != nil {
				problems = append(problems, fmt.Sprintf("%s: expired_at %q is not a %s date", where, e.ExpiredAt, expiryLayout))
			} else {
				if expiry.After(horizon) {
					problems = append(problems, fmt.Sprintf("%s: expires %s, more than %d days out — an expiry that far away is not an expiry",
						where, e.ExpiredAt, maxHorizonDays))
				}
				e.expiry = expiry
			}
		}
		if _, dup := a.byID[e.ID]; dup {
			// Two entries for one id means two different review decisions
			// are on file and the one that applies is chosen by position
			// (CLAUDE.md §3.8).
			problems = append(problems, fmt.Sprintf("%s: listed twice", where))
			continue
		}
		a.byID[e.ID] = e
		a.entries = append(a.entries, e)
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("allowlist %s is not usable:\n  - %s", path, strings.Join(problems, "\n  - "))
	}
	return a, nil
}

// --- govulncheck ---------------------------------------------------------

// govulncheck -format json emits a stream of single-key objects. Only two
// kinds matter here: an "osv" record describing a vulnerability (and, in
// its aliases, the CVE identifiers the allowlist is likely written
// against), and a "finding" placing it in this module's call graph.
type gvcMessage struct {
	Config  *json.RawMessage `json:"config"`
	OSV     *gvcOSV          `json:"osv"`
	Finding *gvcFinding      `json:"finding"`
}

type gvcOSV struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
}

type gvcFinding struct {
	OSV          string     `json:"osv"`
	FixedVersion string     `json:"fixed_version"`
	Trace        []gvcFrame `json:"trace"`
}

type gvcFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

// called reports whether this finding places the vulnerable symbol on a path
// this code actually reaches. govulncheck reports the same vulnerability at
// up to three depths, and only the deepest one — a frame naming a function —
// is the claim that distinguishes govulncheck from a version comparison.
func (f gvcFinding) called() bool {
	return len(f.Trace) > 0 && f.Trace[0].Function != ""
}

func judgeGovulncheck(r io.Reader, out io.Writer, a *allowlist, now time.Time) error {
	osvs := map[string]gvcOSV{}
	var findings []gvcFinding

	dec := json.NewDecoder(r)
	sawConfig := false
	for {
		var msg gvcMessage
		if err := dec.Decode(&msg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("parsing govulncheck output: %w", err)
		}
		switch {
		case msg.Config != nil:
			sawConfig = true
		case msg.OSV != nil:
			osvs[msg.OSV.ID] = *msg.OSV
		case msg.Finding != nil:
			findings = append(findings, *msg.Finding)
		}
	}
	// govulncheck opens every run with a config record. Its absence means
	// the scan did not run to completion — a crash, a truncated pipe, an
	// empty file — and since JSON mode reports a clean run and a dead one
	// with the same exit status, silence here would otherwise read as "no
	// vulnerabilities" (CLAUDE.md §3.4).
	if !sawConfig {
		return errors.New("govulncheck output carries no config record: the scan did not run to completion, so its silence is not a clean result")
	}

	var blocking, suppressed []string
	other := map[string]int{}
	for _, f := range findings {
		if !f.called() {
			level := "required by go.mod, not imported"
			if f.Trace[0].Package != "" {
				level = "imported, not called"
			}
			other[level]++
			continue
		}
		frame := f.Trace[0]
		osv := osvs[f.OSV]
		ids := append([]string{f.OSV}, osv.Aliases...)
		line := fmt.Sprintf("%s (%s)\n      %s@%s calls %s.%s, fixed in %s",
			f.OSV, osv.Summary, frame.Module, frame.Version,
			frame.Package, frame.Function, f.FixedVersion)
		if e, ok := a.covers(now, ids...); ok {
			suppressed = append(suppressed, fmt.Sprintf("%s\n      accepted until %s: %s", line, e.ExpiredAt, e.Statement))
			continue
		}
		blocking = append(blocking, line)
	}
	sort.Strings(blocking)
	sort.Strings(suppressed)

	levels := make([]string, 0, len(other))
	for k := range other {
		levels = append(levels, k)
	}
	sort.Strings(levels)
	for _, k := range levels {
		fmt.Fprintf(out, "note: %d finding(s) %s — not reachable, so not blocking here; trivy fs is the gate for those\n", other[k], k)
	}
	for _, s := range suppressed {
		fmt.Fprintf(out, "allowed: %s\n", s)
	}
	if len(blocking) == 0 {
		fmt.Fprintln(out, "govulncheck: no reachable vulnerability")
		return nil
	}
	for _, b := range blocking {
		fmt.Fprintf(out, "BLOCKING: %s\n", b)
	}
	return fmt.Errorf("%d reachable vulnerabilit%s with no accepted exception", len(blocking), plural(len(blocking)))
}

// plural spells the -y/-ies suffix so counts read as English in the log.
func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
