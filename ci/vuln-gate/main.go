// Command vuln-gate decides whether a dependency scan blocks the build,
// and is the only place an exception may be granted.
//
// Two measured properties of the scanners make "run it and check $?" the
// wrong gate. govulncheck with -format json exits 0 even when it finds a
// called vulnerability (measured against golang.org/x/text v0.3.0). trivy
// honours an ignore entry with no expiry date forever. So the allowlist is
// one reviewed file in trivy's ignorefile schema; trivy reads it directly,
// and this program validates it and applies it to govulncheck.
//
// trivy fs asks whether a vulnerable version is present. govulncheck asks
// whether this code reaches the vulnerable function. This gate fails on a
// govulncheck finding only when the symbol is called. Findings at the
// imported and required levels are printed; trivy already blocks on them.
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

// expiryLayout is the date form trivy's ignorefile uses.
const expiryLayout = "2006-01-02"

// run takes its clock and streams explicitly, so a test can move the
// clock.
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
			// An expired entry stops suppressing, so the finding comes back.
			fmt.Fprintf(out, "  EXPIRED %s (on %s): no longer suppressed, remove it or re-review\n",
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

// allowEntry is one accepted finding, in trivy's ignorefile schema, so one
// file serves both scanners.
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

// covers reports whether any of the identifiers naming one vulnerability
// is allowlisted and in force. govulncheck names a vulnerability by its
// GO- id while the allowlist is usually written against the CVE.
func (a *allowlist) covers(now time.Time, ids ...string) (allowEntry, bool) {
	for _, id := range ids {
		if e, ok := a.byID[id]; ok && !e.expired(now) {
			return e, true
		}
	}
	return allowEntry{}, false
}

// loadAllowlist reads and validates the file. Every defect makes the gate
// refuse to run, because a misread allowlist suppresses a vulnerability. A
// missing file is not a defect: a repository with no accepted findings has
// no allowlist.
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
			problems = append(problems, fmt.Sprintf("%s: no statement; an exception nobody wrote a reason for cannot be reviewed", where))
		}
		if e.ExpiredAt == "" {
			// trivy would suppress this forever.
			problems = append(problems, fmt.Sprintf("%s: no expired_at; an exception with no expiry is a forgotten risk", where))
		} else {
			expiry, perr := time.Parse(expiryLayout, e.ExpiredAt)
			if perr != nil {
				problems = append(problems, fmt.Sprintf("%s: expired_at %q is not a %s date", where, e.ExpiredAt, expiryLayout))
			} else {
				if expiry.After(horizon) {
					problems = append(problems, fmt.Sprintf("%s: expires %s, more than %d days out; an expiry that far away is not an expiry",
						where, e.ExpiredAt, maxHorizonDays))
				}
				e.expiry = expiry
			}
		}
		if _, dup := a.byID[e.ID]; dup {
			// Two entries for one id are two review decisions, and position
			// would choose between them.
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

// govulncheck -format json emits a stream of single-key objects. Two
// kinds matter here: an "osv" record describing a vulnerability, with the
// CVE aliases the allowlist is written against, and a "finding" placing it
// in this module's call graph.
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

// called reports whether the finding places the vulnerable symbol on a
// path this code reaches. govulncheck reports the same vulnerability at up
// to three depths; only the deepest names a function.
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
	// the scan did not complete, and JSON mode reports a dead run with the
	// same exit status as a clean one.
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
		fmt.Fprintf(out, "note: %d finding(s) %s, not reachable, so not blocking here; trivy fs is the gate for those\n", other[k], k)
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

// plural spells the -y or -ies suffix.
func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
