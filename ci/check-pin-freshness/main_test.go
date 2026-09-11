package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shape of the real ci/scanner-pins.sh, trimmed to one of each kind:
// a version-tagged image, a floating-tagged image, an alias, a module, and
// a function that must not be read as a pin.
const pinsFixture = `# Pinned third-party references, in one place.

# aquasec/trivy:0.67.0
TRIVY_IMAGE="aquasec/trivy@sha256:` + sixtyFour + `"

# ghcr.io/opentofu/opentofu:1.12.6. Must stay >= the required_version in
# deploy/terraform/environments/*/versions.tf.
TOFU_IMAGE="ghcr.io/opentofu/opentofu@sha256:` + sixtyFour + `"

# alpine:3. Used for one root-owned file operation at a time.
ALPINE_IMAGE="alpine@sha256:` + sixtyFour + `"
TOFU_CLEANUP_IMAGE="$ALPINE_IMAGE"

# golang.org/x/vuln/cmd/govulncheck. A module version rather than an image.
GOVULNCHECK_VERSION="v1.7.0"

buildGoImage() {
    local dockerfile="$1" matches
}
`

const sixtyFour = "1111111111111111111111111111111111111111111111111111111111111111"

func TestParsePins(t *testing.T) {
	pins, err := ParsePins(pinsFixture)
	if err != nil {
		t.Fatalf("ParsePins: %v", err)
	}
	got := map[string]Pin{}
	for _, p := range pins {
		got[p.Variable] = p
	}
	// TOFU_CLEANUP_IMAGE aliases another pin and carries no digest of its
	// own; checking it would check ALPINE_IMAGE twice.
	if _, ok := got["TOFU_CLEANUP_IMAGE"]; ok {
		t.Error("the alias TOFU_CLEANUP_IMAGE was read as a pin of its own")
	}
	if len(pins) != 4 {
		t.Fatalf("got %d pins, want 4: %v", len(pins), pins)
	}

	for _, tc := range []struct {
		name              string
		registry, repo    string
		tag, module, vers string
	}{
		{"TRIVY_IMAGE", "docker.io", "aquasec/trivy", "0.67.0", "", ""},
		{"TOFU_IMAGE", "ghcr.io", "opentofu/opentofu", "1.12.6", "", ""},
		// alpine is a single-segment Docker Hub name, so it resolves
		// under library/.
		{"ALPINE_IMAGE", "docker.io", "library/alpine", "3", "", ""},
		{"GOVULNCHECK_VERSION", "", "", "", "golang.org/x/vuln/cmd/govulncheck", "v1.7.0"},
	} {
		p, ok := got[tc.name]
		if !ok {
			t.Errorf("%s was not parsed", tc.name)
			continue
		}
		if p.Registry != tc.registry || p.Repo != tc.repo || p.Tag != tc.tag {
			t.Errorf("%s: got registry=%q repo=%q tag=%q, want %q %q %q",
				tc.name, p.Registry, p.Repo, p.Tag, tc.registry, tc.repo, tc.tag)
		}
		if p.Module != tc.module || p.Version != tc.vers {
			t.Errorf("%s: got module=%q version=%q, want %q %q", tc.name, p.Module, p.Version, tc.module, tc.vers)
		}
	}
}

// A pin the parser cannot read must fail rather than be skipped. A skip
// would drop it out of the refresh mechanism silently, which is the exact
// failure this command exists to prevent.
func TestParsePinsFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, src, want string
	}{
		{
			name: "no comment above the assignment",
			src:  "\nTRIVY_IMAGE=\"aquasec/trivy@sha256:" + sixtyFour + "\"\n",
			want: "has no comment above it",
		},
		{
			name: "comment names no tag",
			src:  "# aquasec/trivy\nTRIVY_IMAGE=\"aquasec/trivy@sha256:" + sixtyFour + "\"\n",
			want: "names no tag",
		},
		{
			name: "comment names a different image",
			src:  "# aquasec/trivi:0.67.0\nTRIVY_IMAGE=\"aquasec/trivy@sha256:" + sixtyFour + "\"\n",
			want: "comment names",
		},
		{
			name: "no digest and the comment is not a module path",
			src:  "# just some prose\nGOVULNCHECK_VERSION=\"v1.7.0\"\n",
			want: "not a module path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePins(tc.src)
			if err == nil {
				t.Fatal("want an error, got none")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestSplitImage(t *testing.T) {
	for _, tc := range []struct{ in, registry, repo string }{
		{"alpine", "docker.io", "library/alpine"},
		{"aquasec/trivy", "docker.io", "aquasec/trivy"},
		{"ghcr.io/opentofu/opentofu", "ghcr.io", "opentofu/opentofu"},
		{"localhost:5000/thing", "localhost:5000", "thing"},
	} {
		reg, repo := splitImage(tc.in)
		if reg != tc.registry || repo != tc.repo {
			t.Errorf("splitImage(%q) = %q, %q; want %q, %q", tc.in, reg, repo, tc.registry, tc.repo)
		}
	}
}

// newest must ignore the per-architecture and pre-release tags upstream
// publishes beside its releases, and must not swap the pinned tag's own
// v-prefix convention.
func TestNewestIgnoresNonReleaseTagsAndKeepsThePrefix(t *testing.T) {
	tags := []string{
		"1.6.0-alpha1-arm64", "1.6.0-alpha1", "latest", "1.9.2",
		"1.12.6", "1.10.7", "v2.0.0", "1.12.6-amd64",
	}
	got, ok := newest(tags, version{prefix: "", maj: 1, min: 0, patc: 0})
	if !ok {
		t.Fatal("newest found nothing")
	}
	// v2.0.0 is higher but carries the other prefix convention.
	if got.String() != "1.12.6" {
		t.Errorf("newest = %s, want 1.12.6", got)
	}

	got, ok = newest(tags, version{prefix: "v", maj: 1, min: 0, patc: 0})
	if !ok || got.String() != "v2.0.0" {
		t.Errorf("newest with a v prefix = %s (%v), want v2.0.0", got, ok)
	}
}

// ─── Fakes. No test in this package reaches the network. ─────────────────

type fakeRegistry struct {
	tags    map[string][]string
	digests map[string]string
	err     error
}

func (f fakeRegistry) Tags(_ context.Context, registry, repo string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tags[registry+"/"+repo], nil
}

func (f fakeRegistry) Digest(_ context.Context, registry, repo, tag string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.digests[registry+"/"+repo+":"+tag], nil
}

type fakeModules struct {
	latest map[string]string
	err    error
}

func (f fakeModules) Latest(_ context.Context, module string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.latest[module], nil
}

func TestCheck(t *testing.T) {
	reg := fakeRegistry{
		tags: map[string][]string{
			"docker.io/aquasec/trivy":   {"0.67.0", "0.74.0", "latest"},
			"ghcr.io/opentofu/opentofu": {"1.12.6", "1.12.6-arm64"},
		},
		digests: map[string]string{
			"docker.io/library/alpine:3":   "sha256:" + sixtyFour,
			"docker.io/library/registry:2": "sha256:" + strings.Repeat("2", 64),
		},
	}
	mod := fakeModules{latest: map[string]string{"golang.org/x/vuln/cmd/govulncheck": "v1.8.0"}}

	for _, tc := range []struct {
		name       string
		pin        Pin
		wantBehind bool
		wantLatest string
	}{
		{
			name:       "a version tag with a newer release upstream",
			pin:        Pin{Variable: "TRIVY_IMAGE", Registry: "docker.io", Repo: "aquasec/trivy", Tag: "0.67.0", Digest: "sha256:" + sixtyFour},
			wantBehind: true, wantLatest: "0.74.0",
		},
		{
			name:       "a version tag that is the newest release",
			pin:        Pin{Variable: "TOFU_IMAGE", Registry: "ghcr.io", Repo: "opentofu/opentofu", Tag: "1.12.6", Digest: "sha256:" + sixtyFour},
			wantBehind: false, wantLatest: "1.12.6",
		},
		{
			// A floating tag is expected to move. Still pointing at the
			// pinned digest is what "current" means for this kind.
			name:       "a floating tag still on the pinned digest",
			pin:        Pin{Variable: "ALPINE_IMAGE", Registry: "docker.io", Repo: "library/alpine", Tag: "3", Digest: "sha256:" + sixtyFour},
			wantBehind: false, wantLatest: "sha256:" + sixtyFour,
		},
		{
			name:       "a floating tag that has moved off the pinned digest",
			pin:        Pin{Variable: "REGISTRY_IMAGE", Registry: "docker.io", Repo: "library/registry", Tag: "2", Digest: "sha256:" + sixtyFour},
			wantBehind: true, wantLatest: "sha256:" + strings.Repeat("2", 64),
		},
		{
			name:       "a module behind the proxy's latest",
			pin:        Pin{Variable: "GOVULNCHECK_VERSION", Module: "golang.org/x/vuln/cmd/govulncheck", Version: "v1.7.0"},
			wantBehind: true, wantLatest: "v1.8.0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Check(context.Background(), tc.pin, reg, mod)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got.Behind != tc.wantBehind {
				t.Errorf("Behind = %v, want %v (%s)", got.Behind, tc.wantBehind, got.Why)
			}
			if got.Latest != tc.wantLatest {
				t.Errorf("Latest = %q, want %q", got.Latest, tc.wantLatest)
			}
		})
	}
}

// A repository that publishes no tag matching the pinned convention is an
// error, not a silent "current". Reporting current would be the worst
// answer available: it says the pin was checked when nothing was compared.
func TestCheckFailsWhenNothingComparable(t *testing.T) {
	reg := fakeRegistry{tags: map[string][]string{"docker.io/x/y": {"latest", "nightly"}}}
	_, err := Check(context.Background(), Pin{Variable: "X", Registry: "docker.io", Repo: "x/y", Tag: "1.0.0"}, reg, fakeModules{})
	if err == nil {
		t.Fatal("want an error when no upstream tag is a release version")
	}
	if !strings.Contains(err.Error(), "cannot be compared") {
		t.Errorf("error %q does not say the pin could not be compared", err)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.sh")
	src := "# aquasec/trivy:0.67.0\nTRIVY_IMAGE=\"aquasec/trivy@sha256:" + sixtyFour + "\"\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := fakeRegistry{tags: map[string][]string{"docker.io/aquasec/trivy": {"0.67.0", "0.74.0"}}}

	var out bytes.Buffer
	err := run([]string{"-pins", path}, &out, reg, fakeModules{})
	if err == nil {
		t.Error("a pin behind upstream must fail the run")
	}
	if !strings.Contains(out.String(), "BEHIND") || !strings.Contains(out.String(), "0.74.0") {
		t.Errorf("report does not name the stale pin and its upgrade:\n%s", out.String())
	}

	// -report-only is for a run that should surface the same facts without
	// turning a schedule red.
	out.Reset()
	if err := run([]string{"-pins", path, "-report-only"}, &out, reg, fakeModules{}); err != nil {
		t.Errorf("-report-only must not fail: %v", err)
	}
}

// An empty parse is a parsing failure, never an up-to-date repository.
func TestRunRejectsAPinsFileItReadsAsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.sh")
	if err := os.WriteFile(path, []byte("# nothing but prose\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-pins", path}, &bytes.Buffer{}, fakeRegistry{}, fakeModules{})
	if err == nil || !strings.Contains(err.Error(), "declares no pins") {
		t.Errorf("got %v, want a refusal to treat an empty parse as success", err)
	}
}

// The pagination this test covers is the one that already produced a wrong
// answer by hand. GHCR caps a page at 1000 tags and sends no Link header,
// so a client that paginates only when told to stops at 1000 -- and
// opentofu publishes 1570. Truncated, the newest release it could see was
// 1.10.7 while 1.12.6 was already out, which reads as an up-to-date pin
// rather than as an error.
func TestTagsWalksPastAThousandWithoutALinkHeader(t *testing.T) {
	var pages int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/token") {
			fmt.Fprint(w, `{"token":"t"}`)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer t" {
			t.Errorf("tags request carried Authorization %q", got)
		}
		pages++
		last := r.URL.Query().Get("last")
		// Page one: 1000 tags, no Link header, exactly as GHCR answers.
		if last == "" {
			var b strings.Builder
			b.WriteString(`{"tags":[`)
			for i := 0; i < 1000; i++ {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `"1.10.%d"`, i)
			}
			b.WriteString(`]}`)
			fmt.Fprint(w, b.String())
			return
		}
		// Page two: the release the truncated walk never saw.
		fmt.Fprint(w, `{"tags":["1.12.6"]}`)
	}))
	defer srv.Close()

	c := &httpClient{hc: srv.Client()}
	host := strings.TrimPrefix(srv.URL, "https://")
	tags, err := c.Tags(context.Background(), host, "opentofu/opentofu")
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if pages < 2 {
		t.Fatalf("stopped after %d page(s); a 1000-tag page with no Link header must still be continued", pages)
	}
	if len(tags) != 1001 {
		t.Errorf("got %d tags, want 1001", len(tags))
	}
	got, ok := newest(tags, version{})
	if !ok || got.String() != "1.12.6" {
		t.Errorf("newest = %s (%v), want 1.12.6; the second page was not read", got, ok)
	}
}

// The digest of a multi-architecture tag is the index's digest. Without
// the index media types in Accept, a registry answers with one platform's
// manifest, whose digest is not what the pin holds.
func TestDigestAsksForTheIndexMediaTypes(t *testing.T) {
	want := "sha256:" + sixtyFour
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/token") {
			fmt.Fprint(w, `{"token":"t"}`)
			return
		}
		if r.Method != http.MethodHead {
			t.Errorf("method = %s, want HEAD", r.Method)
		}
		if !strings.Contains(r.Header.Get("Accept"), "image.index.v1+json") {
			t.Errorf("Accept %q does not offer the OCI index type", r.Header.Get("Accept"))
		}
		w.Header().Set("Docker-Content-Digest", want)
	}))
	defer srv.Close()

	c := &httpClient{hc: srv.Client()}
	got, err := c.Digest(context.Background(), strings.TrimPrefix(srv.URL, "https://"), "library/alpine", "3")
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if got != want {
		t.Errorf("Digest = %q, want %q", got, want)
	}
}
