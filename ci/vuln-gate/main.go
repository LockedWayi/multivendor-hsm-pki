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

// stringList collects a flag given more than once. The union check needs
// one file per scanner and there is no fixed number of scanners.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// hitsFile is what one scanner's run reports about the allowlist: which
// entries it actually suppressed something with. Written per scanner,
// read back together, because no single scanner can decide that an entry
// is unused -- trivy consumes the allowlist natively and this program
// never sees what it suppressed unless it is handed the report.
type hitsFile struct {
	Scanner string   `json:"scanner"`
	Matched []string `json:"matched"`
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
	var trivyPaths stringList
	fs.Var(&trivyPaths, "trivy", "trivy JSON report to read suppressions from (repeatable); needs --show-suppressed")
	writeHits := fs.String("write-hits", "", "write the allowlist entries this run suppressed something with, as JSON")
	scanner := fs.String("scanner", "", "name recorded in the -write-hits file, for the log line the union check prints")
	var requireUsed stringList
	fs.Var(&requireUsed, "require-used", "hits file to read (repeatable); every in-force entry matched by none of them fails the gate")
	var expectScanner stringList
	fs.Var(&expectScanner, "expect-scanner", "scanner that must be among the hits files (repeatable); a union missing one of them is not a union")
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

	// The union check is its own run: it judges no findings, it reads what
	// the scanners reported about the allowlist and decides whether any
	// entry is carrying nothing.
	if len(requireUsed) > 0 {
		return requireEveryEntryUsed(out, allowlist, now, requireUsed, expectScanner)
	}

	// trivy consumes the allowlist itself, through --ignorefile, so the
	// only way this program learns what trivy suppressed is to be handed
	// the report. --show-suppressed is what puts it there.
	for _, path := range trivyPaths {
		n, err := recordTrivySuppressions(path, allowlist, now)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "trivy %s: %d suppression(s) attributed to the allowlist\n", path, n)
	}

	var judgeErr error
	if *govulnPath != "" {
		src := in
		if *govulnPath != "-" {
			f, err := os.Open(*govulnPath)
			if err != nil {
				return fmt.Errorf("reading govulncheck output: %w", err)
			}
			defer f.Close()
			src = f
		}
		judgeErr = judgeGovulncheck(src, out, allowlist, now)
	}

	// Written even when the judging failed: the hits are a record of this
	// run, and discarding them because something else went wrong would
	// make the union check silently incomplete rather than red.
	if *writeHits != "" {
		if err := writeHitsFile(*writeHits, *scanner, allowlist); err != nil {
			return err
		}
		fmt.Fprintf(out, "allowlist hits written to %s\n", *writeHits)
	}
	return judgeErr
}

// writeHitsFile records which entries suppressed something in this run.
func writeHitsFile(path, scanner string, a *allowlist) error {
	if scanner == "" {
		scanner = "unnamed"
	}
	data, err := json.MarshalIndent(hitsFile{Scanner: scanner, Matched: a.matched()}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding hits: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing hits to %s: %w", path, err)
	}
	return nil
}

// requireEveryEntryUsed fails when an in-force entry suppressed nothing in
// any of the scanner runs it was handed.
//
// Why the union and not one scanner: an entry may legitimately cover a
// finding only trivy sees, or only govulncheck sees. Judged per scanner,
// a correct entry would fail. Judged over all of them, an entry that
// matched nothing anywhere is what it looks like -- an exception nobody
// needs and nobody is reviewing.
//
// An expired entry is not required to be used. It has already stopped
// suppressing, and the EXPIRED line above is its report.
func requireEveryEntryUsed(out io.Writer, a *allowlist, now time.Time, paths, expect []string) error {
	used := map[string]string{} // entry id -> the scanner that matched it
	seen := map[string]bool{}   // scanner name -> it reported
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading hits file: %w", err)
		}
		var h hitsFile
		if err := json.Unmarshal(data, &h); err != nil {
			return fmt.Errorf("parsing hits file %s: %w", path, err)
		}
		if h.Scanner == "" {
			// A hits file with no scanner name cannot be reported
			// usefully, and an unnamed one usually means the wrong file.
			return fmt.Errorf("hits file %s names no scanner", path)
		}
		seen[h.Scanner] = true
		fmt.Fprintf(out, "hits from %s (%s): %d entr%s matched\n", h.Scanner, path, len(h.Matched), plural(len(h.Matched)))
		for _, id := range h.Matched {
			if _, seen := used[id]; !seen {
				used[id] = h.Scanner
			}
		}
	}

	// A union missing a scanner is not a union. Judged over two of three,
	// an entry only the absent one uses reads as unused -- and with an
	// empty allowlist it reads as a clean pass, which is the same defect
	// in the other direction: a scanner whose report never arrived is
	// invisible. So the callers name who must have reported.
	var missing []string
	for _, want := range expect {
		if !seen[want] {
			missing = append(missing, want)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		for _, m := range missing {
			fmt.Fprintf(out, "  MISSING %s: no hits file from this scanner\n", m)
		}
		return fmt.Errorf("%d expected scanner report(s) absent; the verdict would be reached over less than the whole pipeline, and with an empty allowlist that reads as a clean pass",
			len(missing))
	}

	var unused []string
	for _, e := range a.entries {
		if e.expired(now) {
			continue
		}
		if who, ok := used[e.ID]; ok {
			fmt.Fprintf(out, "  in use  %s (matched by %s)\n", e.ID, who)
			continue
		}
		unused = append(unused, e.ID)
	}
	sort.Strings(unused)
	if len(unused) == 0 {
		fmt.Fprintf(out, "allowlist: every entry in force suppressed something\n")
		return nil
	}
	for _, id := range unused {
		fmt.Fprintf(out, "  UNUSED  %s: suppressed nothing in any scanner this run\n", id)
	}
	return fmt.Errorf("%d allowlist entr%s matched nothing; an exception that has stopped matching is an allowance nobody reviews, and it reads exactly like a clean scan. Remove it, or say in its statement why it must stay",
		len(unused), plural(len(unused)))
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
	// hits records which entries actually suppressed something in this
	// run. An entry that suppresses nothing is an allowance nobody
	// reviews and reads exactly like a clean scan, so it has to be
	// observed rather than assumed.
	hits map[string]bool
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
			a.hits[e.ID] = true
			return e, true
		}
	}
	return allowEntry{}, false
}

// matched lists, sorted, the entries that suppressed something.
func (a *allowlist) matched() []string {
	out := make([]string, 0, len(a.hits))
	for id := range a.hits {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// loadAllowlist reads and validates the file. Every defect makes the gate
// refuse to run, because a misread allowlist suppresses a vulnerability. A
// missing file is not a defect: a repository with no accepted findings has
// no allowlist.
func loadAllowlist(path string, now time.Time, maxHorizonDays int) (*allowlist, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &allowlist{byID: map[string]allowEntry{}, hits: map[string]bool{}}, nil
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
	a := &allowlist{
		byID: make(map[string]allowEntry, len(parsed.Vulnerabilities)),
		hits: make(map[string]bool, len(parsed.Vulnerabilities)),
	}
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

// --- trivy ---------------------------------------------------------------

// trivyReport is the part of `trivy --format json --show-suppressed` this
// program reads. Everything else in the report is the gate's business and
// trivy's own --exit-code already decided it.
//
// ExperimentalModifiedFindings is trivy's name for what the ignorefile
// removed, and it is experimental in 0.74.0.
//
// A limit this program cannot work around, measured rather than assumed:
// a report from a run that suppressed nothing and a report from a run
// that was never asked for suppressions are **byte-identical in this
// respect**. Both omit the field entirely, and nothing in the report's
// metadata records which flags ran -- `Trivy: {"Version": "0.74.0"}` is
// all there is. So vuln-gate cannot verify that --show-suppressed was
// passed, and a caller that forgets it produces an empty hits file,
// which marks every entry unused: red, but for the wrong reason.
//
// The guarantee therefore lives where it can be enforced, at the point
// the command is built. requireSuppressionReporting in ci/scanner-pins.sh
// refuses to run trivy with --ignorefile unless --show-suppressed is
// there too.
type trivyReport struct {
	Results []struct {
		Target   string `json:"Target"`
		Modified []struct {
			Type      string `json:"Type"`
			Status    string `json:"Status"`
			Statement string `json:"Statement"`
			Source    string `json:"Source"`
			Finding   struct {
				VulnerabilityID string `json:"VulnerabilityID"`
			} `json:"Finding"`
		} `json:"ExperimentalModifiedFindings"`
	} `json:"Results"`
}

// recordTrivySuppressions marks the allowlist entries trivy used, and
// returns how many suppressions it attributed to them.
//
// An id trivy suppressed that is not in the allowlist is not counted: it
// came from somewhere else, and this program only speaks for one file.
func recordTrivySuppressions(path string, a *allowlist, now time.Time) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading trivy report: %w", err)
	}
	var r trivyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return 0, fmt.Errorf("parsing trivy report %s: %w", path, err)
	}
	n := 0
	for _, res := range r.Results {
		for _, m := range res.Modified {
			if m.Status != "ignored" {
				continue
			}
			if _, ok := a.covers(now, m.Finding.VulnerabilityID); ok {
				n++
			}
		}
	}
	return n, nil
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
