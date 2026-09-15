// Command check-pin-freshness reports pinned third-party references that
// have fallen behind upstream.
//
//	go run ./ci/check-pin-freshness
//	go run ./ci/check-pin-freshness -pins ci/scanner-pins.sh -report-only
//
// Dependabot cannot see these. Its docker ecosystem reads Dockerfile FROM
// lines and its github-actions ecosystem reads uses: values; a digest held
// anywhere else is invisible to it. ci/scanner-pins.sh is exactly that
// somewhere else, and its pins rot silently -- nothing breaks, they just
// stop receiving the fixes a tag would have brought.
//
// Two pin kinds are checked, because they have different failure modes:
//
//   - A version tag (0.67.0, v8.30.1) is answered by listing the upstream
//     tags and finding the newest release. The pinned digest is expected
//     never to move; a newer version existing is the finding.
//   - A floating tag (3, 2) is answered by resolving that tag now and
//     comparing the digest. The tag is expected to move, and its having
//     moved means a newer build exists under the same major.
//
// A Go module version is checked against the module proxy instead.
//
// This is deliberately not a pull-request gate. Upstream shipping a release
// is not a reason to fail somebody's unrelated change. It runs on a
// schedule.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	c := &httpClient{hc: &http.Client{Timeout: 30 * time.Second}}
	if err := run(os.Args[1:], os.Stdout, c, c); err != nil {
		fmt.Fprintf(os.Stderr, "check-pin-freshness: %v\n", err)
		os.Exit(1)
	}
}

// Registry lists tags and resolves one tag to a digest. Both are the OCI
// distribution API, which Docker Hub and GHCR both serve anonymously, so
// one code path covers every registry this repository pins from.
type Registry interface {
	Tags(ctx context.Context, registry, repo string) ([]string, error)
	Digest(ctx context.Context, registry, repo, tag string) (string, error)
}

// Modules resolves a Go module's latest released version.
type Modules interface {
	Latest(ctx context.Context, module string) (string, error)
}

// Pin is one pinned reference read from the pins file.
type Pin struct {
	// Variable is the shell variable the pin is assigned to.
	Variable string
	// Ref is what the comment above the assignment names: an image
	// reference with a tag, or a Go module path.
	Ref string
	// Registry and Repo are set for image pins. Registry is a host;
	// Repo is the path within it, already namespaced ("library/alpine").
	Registry, Repo string
	// Tag is the image tag named in the comment.
	Tag string
	// Digest is the sha256:... the assignment pins, empty for a module.
	Digest string
	// Module and Version are set for a Go module pin.
	Module, Version string
}

// IsModule reports whether this pin names a Go module rather than an image.
func (p Pin) IsModule() bool { return p.Module != "" }

// Result is one pin's verdict.
type Result struct {
	Pin Pin
	// Behind is true when upstream has something newer.
	Behind bool
	// Latest is what upstream offers: a version, or a digest for a
	// floating tag.
	Latest string
	// Why states the comparison in one line, for the report.
	Why string
}

var (
	assignRE = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)="([^"]*)"$`)
	digestRE = regexp.MustCompile(`^(.+)@(sha256:[0-9a-f]{64})$`)
	semverRE = regexp.MustCompile(`^(v?)(\d+)\.(\d+)\.(\d+)$`)
)

// ParsePins reads the pins file and returns one Pin per pinned reference.
//
// The convention it enforces is the one the file already uses: the first
// line of the comment block directly above an assignment names what the
// digest below it pins.
//
//	# aquasec/trivy:0.67.0
//	TRIVY_IMAGE="aquasec/trivy@sha256:..."
//
// An assignment whose comment cannot be read is an error rather than a
// skip. A silent skip would mean a pin added without a readable comment
// quietly leaves the refresh mechanism, which is the exact failure this
// command exists to prevent.
func ParsePins(src string) ([]Pin, error) {
	var pins []Pin
	var block []string
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimRight(raw, " \t")
		switch {
		case strings.HasPrefix(line, "#"):
			block = append(block, strings.TrimSpace(strings.TrimPrefix(line, "#")))
			continue
		case line == "":
			block = nil
			continue
		}
		m := assignRE.FindStringSubmatch(line)
		if m == nil {
			// Anything else -- a function, a `cd`, a bare statement --
			// ends the comment block without being a pin.
			block = nil
			continue
		}
		name, value := m[1], m[2]
		// An alias of another pin carries no digest of its own and is
		// checked where it is defined.
		if strings.HasPrefix(value, "$") {
			block = nil
			continue
		}
		pin, err := pinFrom(name, value, block)
		if err != nil {
			return nil, err
		}
		pins = append(pins, pin)
		block = nil
	}
	return pins, nil
}

func pinFrom(name, value string, block []string) (Pin, error) {
	if len(block) == 0 {
		return Pin{}, fmt.Errorf("%s has no comment above it; the line above a pin must name what it pins, as `# aquasec/trivy:0.67.0`", name)
	}
	// The first word of the block's first line. The rest of the block is
	// prose for a human and is not read here.
	ref := strings.TrimSuffix(strings.Fields(block[0])[0], ".")

	if dm := digestRE.FindStringSubmatch(value); dm != nil {
		image, digest := dm[1], dm[2]
		named, tag, ok := strings.Cut(ref, ":")
		if !ok {
			return Pin{}, fmt.Errorf("%s pins the image %q, but its comment %q names no tag; write `# %s:<tag>` so the tag can be resolved upstream", name, image, block[0], image)
		}
		if named != image {
			return Pin{}, fmt.Errorf("%s pins %q but its comment names %q; the comment is what this check resolves upstream, so a comment that names a different image checks the wrong thing", name, image, named)
		}
		registry, repo := splitImage(image)
		return Pin{Variable: name, Ref: ref, Registry: registry, Repo: repo, Tag: tag, Digest: digest}, nil
	}

	// No digest: a module version, whose immutability comes from the
	// proxy's checksum database rather than from a digest.
	if !strings.Contains(ref, "/") || strings.Contains(ref, ":") {
		return Pin{}, fmt.Errorf("%s=%q has no digest, so it is read as a Go module version, but its comment %q is not a module path", name, value, block[0])
	}
	return Pin{Variable: name, Ref: ref, Module: ref, Version: value}, nil
}

// splitImage separates a registry host from the repository path and
// applies Docker Hub's two defaults: an image with no host lives on
// docker.io, and a single-segment name there lives under library/.
func splitImage(image string) (registry, repo string) {
	host, rest, ok := strings.Cut(image, "/")
	if !ok || !strings.ContainsAny(host, ".:") {
		registry, repo = "docker.io", image
	} else {
		registry, repo = host, rest
	}
	if registry == "docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return registry, repo
}

// version is a parsed release tag. Only exact MAJOR.MINOR.PATCH tags are
// parsed: upstream repositories publish per-architecture and pre-release
// tags beside their releases (opentofu ships 1.6.0-alpha1-arm64), and
// selecting one of those as "newest" would report an upgrade nobody should
// take.
type version struct {
	prefix         string // "v" or ""
	maj, min, patc int
}

func parseVersion(tag string) (version, bool) {
	m := semverRE.FindStringSubmatch(tag)
	if m == nil {
		return version{}, false
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	return version{prefix: m[1], maj: n(m[2]), min: n(m[3]), patc: n(m[4])}, true
}

func (v version) String() string {
	return fmt.Sprintf("%s%d.%d.%d", v.prefix, v.maj, v.min, v.patc)
}

func (v version) less(o version) bool {
	if v.maj != o.maj {
		return v.maj < o.maj
	}
	if v.min != o.min {
		return v.min < o.min
	}
	return v.patc < o.patc
}

// newest returns the highest version among tags that share want's prefix
// convention. The prefix is part of the match because a repository that
// publishes both 1.2.3 and v1.2.3 would otherwise have its pinned
// convention silently swapped.
func newest(tags []string, want version) (version, bool) {
	var best version
	found := false
	for _, t := range tags {
		v, ok := parseVersion(t)
		if !ok || v.prefix != want.prefix {
			continue
		}
		if !found || best.less(v) {
			best, found = v, true
		}
	}
	return best, found
}

// Check resolves one pin against upstream.
func Check(ctx context.Context, p Pin, reg Registry, mod Modules) (Result, error) {
	if p.IsModule() {
		latest, err := mod.Latest(ctx, p.Module)
		if err != nil {
			return Result{}, fmt.Errorf("%s: %w", p.Variable, err)
		}
		have, ok := parseVersion(p.Version)
		if !ok {
			return Result{}, fmt.Errorf("%s pins %q, which is not a MAJOR.MINOR.PATCH version", p.Variable, p.Version)
		}
		want, ok := parseVersion(latest)
		if !ok {
			return Result{}, fmt.Errorf("%s: the module proxy reports %q as the latest version of %s, which is not a MAJOR.MINOR.PATCH version", p.Variable, latest, p.Module)
		}
		return Result{
			Pin: p, Behind: have.less(want), Latest: want.String(),
			Why: fmt.Sprintf("pinned %s, latest %s", have, want),
		}, nil
	}

	if have, ok := parseVersion(p.Tag); ok {
		tags, err := reg.Tags(ctx, p.Registry, p.Repo)
		if err != nil {
			return Result{}, fmt.Errorf("%s: %w", p.Variable, err)
		}
		want, found := newest(tags, have)
		if !found {
			return Result{}, fmt.Errorf("%s: %s/%s published %d tags and none is a %s-prefixed MAJOR.MINOR.PATCH version, so the pinned tag %q cannot be compared", p.Variable, p.Registry, p.Repo, len(tags), have.prefix+"…", p.Tag)
		}
		return Result{
			Pin: p, Behind: have.less(want), Latest: want.String(),
			Why: fmt.Sprintf("pinned %s, latest %s", have, want),
		}, nil
	}

	// A floating tag. The question is not "is there a newer version" but
	// "has the tag moved off the digest we pinned", which is the same
	// question asked of a pointer rather than of a name.
	digest, err := reg.Digest(ctx, p.Registry, p.Repo, p.Tag)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", p.Variable, err)
	}
	return Result{
		Pin: p, Behind: digest != p.Digest, Latest: digest,
		Why: fmt.Sprintf("%s:%s resolves to %s, pinned %s", p.Repo, p.Tag, short(digest), short(p.Digest)),
	}, nil
}

func short(digest string) string {
	if len(digest) > 19 {
		return digest[:19] + "…"
	}
	return digest
}

func run(args []string, out io.Writer, reg Registry, mod Modules) error {
	fs := flag.NewFlagSet("check-pin-freshness", flag.ContinueOnError)
	fs.SetOutput(out)
	pinsPath := fs.String("pins", "ci/scanner-pins.sh", "the pins file to read")
	reportOnly := fs.Bool("report-only", false, "print the report and exit 0 even when a pin is behind")
	if err := fs.Parse(args); err != nil {
		return err
	}
	src, err := os.ReadFile(*pinsPath)
	if err != nil {
		return err
	}
	pins, err := ParsePins(string(src))
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		return fmt.Errorf("%s declares no pins; a pins file this check reads as empty is a parsing failure, not an up-to-date repository", *pinsPath)
	}

	ctx := context.Background()
	results := make([]Result, 0, len(pins))
	var errs []error
	for _, p := range pins {
		r, err := Check(ctx, p, reg, mod)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		results = append(results, r)
	}
	// Every pin is reported before anything fails. A checker that stops at
	// the first stale pin turns one upgrade into as many runs as there are
	// pins.
	sort.Slice(results, func(i, j int) bool { return results[i].Pin.Variable < results[j].Pin.Variable })

	behind := 0
	for _, r := range results {
		state := "current"
		if r.Behind {
			state = "BEHIND "
			behind++
		}
		fmt.Fprintf(out, "  %s  %-24s %s\n", state, r.Pin.Variable, r.Why)
	}
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(out, "  ERROR    %v\n", e)
		}
		return fmt.Errorf("%d of %d pins could not be checked", len(errs), len(pins))
	}
	if behind == 0 {
		fmt.Fprintf(out, "\n%d pins, all current\n", len(results))
		return nil
	}
	fmt.Fprintf(out, "\n%d of %d pins are behind upstream.\n", behind, len(results))
	if *reportOnly {
		return nil
	}
	return errors.New("pinned references have fallen behind; bump them in the pins file")
}

// ─── The upstream clients ────────────────────────────────────────────────

type httpClient struct{ hc *http.Client }

// tokenFor gets an anonymous pull token. Both registries this repository
// pins from hand one out without credentials; the request is required
// even so, because the distribution API answers 401 without a bearer.
func (c *httpClient) tokenFor(ctx context.Context, registry, repo string) (string, error) {
	var url string
	switch registry {
	case "docker.io":
		url = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:" + repo + ":pull"
	default:
		url = "https://" + registry + "/token?service=" + registry + "&scope=repository:" + repo + ":pull"
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := c.getJSON(ctx, url, "", &body); err != nil {
		return "", err
	}
	if body.Token == "" {
		return "", fmt.Errorf("%s issued an empty pull token for %s", registry, repo)
	}
	return body.Token, nil
}

func registryHost(registry string) string {
	if registry == "docker.io" {
		return "registry-1.docker.io"
	}
	return registry
}

// Tags lists every tag, walking the distribution API's `last=`
// continuation.
//
// The continuation is walked explicitly rather than by following a Link
// header: GHCR caps a page at 1000 tags and sends no Link header at all,
// so a client that paginates only when told to stops at 1000. opentofu
// publishes 1570, and truncating there reported 1.10.7 as the newest
// release when 1.12.6 was already out -- an answer that looks like a
// current pin.
func (c *httpClient) Tags(ctx context.Context, registry, repo string) ([]string, error) {
	token, err := c.tokenFor(ctx, registry, repo)
	if err != nil {
		return nil, err
	}
	host := registryHost(registry)
	var all []string
	last := ""
	// A bound, so a registry that ignores `last=` cannot spin forever.
	for page := 0; page < 50; page++ {
		url := fmt.Sprintf("https://%s/v2/%s/tags/list?n=1000", host, repo)
		if last != "" {
			last = strings.ReplaceAll(last, " ", "%20")
			url += "&last=" + last
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		if err := c.getJSON(ctx, url, token, &body); err != nil {
			return nil, err
		}
		if len(body.Tags) == 0 {
			break
		}
		all = append(all, body.Tags...)
		if len(body.Tags) < 1000 {
			break
		}
		last = body.Tags[len(body.Tags)-1]
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("%s/%s lists no tags", registry, repo)
	}
	return all, nil
}

// Digest resolves a tag to the digest the registry currently serves for
// it, read from Docker-Content-Digest on a HEAD.
func (c *httpClient) Digest(ctx context.Context, registry, repo, tag string) (string, error) {
	token, err := c.tokenFor(ctx, registry, repo)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registryHost(registry), repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// Without the index types the registry answers with a single
	// platform's manifest, whose digest is not the digest a multi-arch
	// tag is pinned by.
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HEAD %s: %s", url, resp.Status)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("HEAD %s returned no Docker-Content-Digest", url)
	}
	return digest, nil
}

// Latest asks the module proxy for a module's newest released version.
//
// The path given may be a package rather than a module: the pins file
// names golang.org/x/vuln/cmd/govulncheck, which is what an operator
// installs, while the module that carries a version is golang.org/x/vuln.
// So trailing elements are dropped until the proxy answers, which is how
// the go command finds a package's containing module. Making the comment
// name the module instead would be the other fix, and it would make the
// file name something nobody types.
//
// The walk stops at the first two elements, so a typo cannot climb to a
// host and resolve some unrelated module.
func (c *httpClient) Latest(ctx context.Context, pkg string) (string, error) {
	parts := strings.Split(pkg, "/")
	var lastErr error
	for len(parts) >= 2 {
		candidate := strings.Join(parts, "/")
		// An upper-case letter in a module path needs !-escaping for the
		// proxy. None of this repository's pins has one, and one that did
		// would fail on the 404 rather than resolve the wrong module.
		var body struct {
			Version string `json:"Version"`
		}
		err := c.getJSON(ctx, "https://proxy.golang.org/"+candidate+"/@latest", "", &body)
		if err == nil {
			if body.Version == "" {
				return "", fmt.Errorf("the module proxy reported no version for %s", candidate)
			}
			return body.Version, nil
		}
		lastErr = err
		parts = parts[:len(parts)-1]
	}
	return "", fmt.Errorf("no module along %s answered the proxy: %w", pkg, lastErr)
}

func (c *httpClient) getJSON(ctx context.Context, url, token string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(into)
}
