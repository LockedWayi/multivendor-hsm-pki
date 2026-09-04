// Command generate-image-policy renders the admission policy that decides
// which container images may run, from the published key inventory.
//
// # Why this is generated and not written
//
// CLAUDE.md §3.7 says verifiers consume the inventory, never a hard-coded
// key. An admission policy with a public key pasted into it is exactly the
// hard-coded verifier that rule forbids, and the failure it produces is the
// expensive kind: on the day `image-signing-key-v1` is rotated, images
// signed by `-v2` are refused at admission and images signed by `-v1` still
// pass, until somebody remembers this file. Rotation would then be a
// breaking change to the cluster, which in practice means it never happens.
//
// So the policy holds every key the inventory calls verifiable for the
// image purpose -- `active` and `verify-only` together, which is what makes
// a transition window expressible at all. Regenerating after a rotation is
// one command, and the diff shows exactly which keys the cluster will trust.
//
// # What it emits
//
//	ImageValidatingPolicy  require-signed-images   every image carries a
//	                                               signature by a key the
//	                                               inventory vouches for
//	ValidatingPolicy       require-image-digest    every image is named by
//	                                               digest, never by tag
//
// The second is not a nicety. A signature is over a digest, so a tag-named
// image is a pointer that can be repointed after admission has approved it
// (CLAUDE.md §3.8). Kyverno would resolve the tag and verify whatever it
// resolved to, which answers a question about this instant rather than
// about the thing that will run.
//
// # The document is verified before it is believed
//
// The inventory is signed precisely so that editing the file is not enough
// to change what a verifier trusts — and this generator is a verifier: its
// output IS what the cluster trusts. An earlier version read the document
// and never the signature beside it, so a tampered inventory rendered
// straight into an admission policy carrying the tamperer's key; the only
// signature check lived in the test suite, which made the deploy path's
// safety a convention ("the tests ran first") rather than a property of
// the tool. Found by an independent audit, 2026-09-04.
//
// So three refusals now sit in front of the template, each fail-closed
// (CLAUDE.md §3.4):
//
//   - the detached signature must verify against the anchor
//     (inventory-signing-key-v1.pub beside the inventory by default;
//     -anchor and -signature override the paths, never the requirement);
//   - valid_until must not have passed — a withheld update must not keep
//     yesterday's list, and yesterday's keys, alive forever;
//   - when -out names an existing rendering, the inventory's version must
//     not be lower than the one that rendering was produced from (read
//     from its own header). Stdout mode has no replacement target, so it
//     has no floor to enforce — the committed-policy path is the one this
//     protects.
//
// Usage:
//
//	go run ./ci/generate-image-policy -out deploy/k8s/policy/image-signature.yaml
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/inventory"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "generate-image-policy: %v\n", err)
		os.Exit(1)
	}
}

// attestor is one trusted key, as the policy template needs it.
type attestor struct {
	// Name is a CEL identifier, so it is the label with everything CEL
	// cannot carry removed.
	Name string
	// Label and Status are the inventory's own words, written into the
	// output as a comment so a reader can tell why a key is trusted.
	Label  string
	Status string
	PEM    string
}

type policyData struct {
	Source       string
	InventoryVer int
	// Anchor and ValidUntil record, in the rendered file's own header, what
	// the document was checked against and how long it claimed to be good
	// for — so a reader of the committed policy can see the verification
	// happened without re-deriving it.
	Anchor     string
	ValidUntil string
	Attestors  []attestor
	ExcludedNS []string
	Insecure   bool
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("generate-image-policy", flag.ContinueOnError)
	fs.SetOutput(out)
	invPath := fs.String("inventory", "docs/keys/key-inventory.json", "path to the signed key inventory")
	outPath := fs.String("out", "", "file to write; stdout when empty")
	// Off by default, and it has to be: a policy that will talk plaintext
	// to a registry cannot tell a real registry from anyone who can answer
	// on its address, so the signature it fetches is whatever that party
	// chose to serve. The local k3d registry speaks HTTP, so the dev
	// cluster renders its own copy with this on -- visibly, in a file that
	// says so -- rather than the committed policy carrying the concession
	// for every environment.
	insecure := fs.Bool("allow-insecure-registry", false,
		"let the policy fetch signatures over plaintext HTTP (development registries only)")
	sigPath := fs.String("signature", "",
		"detached signature over the inventory's exact bytes; defaults to <inventory>.sig")
	anchorPath := fs.String("anchor", "",
		"public half of the inventory signing key; defaults to inventory-signing-key-v1.pub beside the inventory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	raw, err := os.ReadFile(filepath.Clean(*invPath))
	if err != nil {
		return fmt.Errorf("reading the inventory: %w", err)
	}

	// The signature is checked before the document is even parsed. Order
	// matters less for security here than for the error a reader gets: a
	// tampered file usually still parses, so parse-first reports nothing,
	// while verify-first names the actual problem — these bytes are not the
	// bytes the offline key signed.
	//
	// The defaults resolve beside the inventory rather than against the
	// working directory, so the documented invocation works from anywhere
	// and the committed layout (docs/keys/ holds all three files) needs no
	// flags at all.
	resolvedSig := *sigPath
	if resolvedSig == "" {
		resolvedSig = *invPath + ".sig"
	}
	resolvedAnchor := *anchorPath
	if resolvedAnchor == "" {
		resolvedAnchor = filepath.Join(filepath.Dir(*invPath), "inventory-signing-key-v1.pub")
	}
	sig, err := os.ReadFile(filepath.Clean(resolvedSig))
	if err != nil {
		return fmt.Errorf("reading the inventory's signature: %w — an inventory without its "+
			"signature is a list of trusted keys anyone could have written; pass -signature "+
			"if it lives somewhere other than beside the inventory", err)
	}
	anchorPEM, err := os.ReadFile(filepath.Clean(resolvedAnchor))
	if err != nil {
		return fmt.Errorf("reading the inventory signing anchor: %w — pass -anchor if it "+
			"lives somewhere other than beside the inventory", err)
	}
	anchor, err := inventory.Entry{Label: filepath.Base(resolvedAnchor), PublicKeyPEM: string(anchorPEM)}.PublicKey()
	if err != nil {
		return fmt.Errorf("parsing the anchor %s: %w", resolvedAnchor, err)
	}
	if err := inventory.Verify(raw, sig, anchor); err != nil {
		return fmt.Errorf("the inventory's signature does not verify against %s: %w — "+
			"a policy rendered from an unverified inventory would let whoever edited the "+
			"file choose which keys the cluster trusts, which is the exact attack the "+
			"signature exists to refuse (CLAUDE.md §3.4, §3.7)", resolvedAnchor, err)
	}

	inv, err := inventory.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing the inventory: %w", err)
	}

	// Freshness: an expired document is refused, not warned about. Without
	// this, an attacker who can only *withhold* inventory updates keeps
	// yesterday's list — and any key it has since retired — trusted forever
	// (the freeze attack valid_until exists for; internal/inventory's
	// package comment names it and correctly says it cannot enforce it
	// alone — this is the consumer-side half).
	if now := time.Now(); now.After(inv.ValidUntil) {
		return fmt.Errorf("the inventory expired at %s (now %s): a stale list of trusted keys "+
			"is refused rather than rendered — regenerate and re-sign it with "+
			"hsm-pki-keytool generate-inventory", inv.ValidUntil.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	// Rollback: when this run replaces an existing rendering, the incoming
	// inventory may not be older than the one that rendering came from — an
	// old document can resurrect a retired key. The floor is read from the
	// -out file's own header, which this generator has always written.
	// Stdout mode replaces nothing, so it has no floor to enforce; the
	// committed-policy path is the durable artifact this protects.
	if *outPath != "" {
		prev, err := previousRenderedVersion(*outPath)
		if err != nil {
			return err
		}
		if prev > 0 && inv.Version < prev {
			return fmt.Errorf("the inventory is version %d but %s was rendered from version %d: "+
				"refusing the rollback — an older list can resurrect a retired key. If replacing "+
				"the rendering with an older inventory is genuinely intended, move the existing "+
				"file aside first, so the decision is somebody's rather than this tool's "+
				"(CLAUDE.md §3.4)", inv.Version, *outPath, prev)
		}
	}

	verifiable := inv.Verifiable(inventory.PurposeImage)
	if len(verifiable) == 0 {
		// Refused rather than emitted. A policy with no attestors rejects
		// every image, which is fail-closed and also useless -- it would
		// stop the cluster and read as a broken policy rather than as an
		// empty inventory (CLAUDE.md §3.4).
		return fmt.Errorf("the inventory lists no active or verify-only key for the image purpose, "+
			"so there is nothing for the cluster to trust; provision one before generating a policy (%s)", *invPath)
	}

	seen := map[string]string{}
	var attestors []attestor
	for _, e := range verifiable {
		name := celIdentifier(e.Label)
		if name == "" {
			return fmt.Errorf("key label %q has no characters CEL can carry in an identifier", e.Label)
		}
		// Two labels collapsing to one identifier would silently drop a
		// key the inventory vouches for, so it fails rather than picks.
		if prev, dup := seen[name]; dup {
			return fmt.Errorf("key labels %q and %q both become the CEL identifier %q; "+
				"rename one before generating a policy", prev, e.Label, name)
		}
		seen[name] = e.Label
		attestors = append(attestors, attestor{
			Name:   name,
			Label:  e.Label,
			Status: string(e.Status),
			PEM:    strings.TrimRight(e.PublicKeyPEM, "\n"),
		})
	}

	// Every list a pod can carry an image in. Enumerated rather than
	// discovered, so a fourth one appearing in a future Kubernetes is a
	// change somebody makes deliberately instead of a gap nobody sees.
	lists := []string{"containers", "initContainers", "ephemeralContainers"}

	var buf bytes.Buffer
	if err := policyTemplate.Execute(&buf, struct {
		policyData
		Lists []string
	}{
		policyData: policyData{
			Source:       *invPath,
			InventoryVer: inv.Version,
			Anchor:       filepath.ToSlash(resolvedAnchor),
			ValidUntil:   inv.ValidUntil.Format(time.RFC3339),
			Attestors:    attestors,
			ExcludedNS:   []string{"kube-system", "kube-public", "kube-node-lease", "kyverno"},
			Insecure:     *insecure,
		},
		Lists: lists,
	}); err != nil {
		return fmt.Errorf("rendering the policy: %w", err)
	}

	if *outPath == "" {
		_, err := out.Write(buf.Bytes())
		return err
	}
	if err := os.WriteFile(*outPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", *outPath, err)
	}
	fmt.Fprintf(out, "wrote %s: %d trusted image key(s) from %s version %d\n",
		*outPath, len(attestors), *invPath, inv.Version)
	if *insecure {
		fmt.Fprintf(out, "  WARNING: plaintext registry access is enabled in this rendering\n")
	}
	for _, a := range attestors {
		fmt.Fprintf(out, "  %-28s %s\n", a.Label, a.Status)
	}
	return nil
}

// renderedVersionPattern matches the header line every rendering carries
// ("Rendered from <path> (version N) by"), which is where the rollback
// check's floor comes from.
var renderedVersionPattern = regexp.MustCompile(`Rendered from .+ \(version ([0-9]+)\)`)

// previousRenderedVersion reads the inventory version out of the rendering
// being replaced. It returns 0 when nothing exists at path yet — there is
// no floor to enforce against a file that is not there.
//
// A file that exists but carries no version header is refused rather than
// treated as version 0: it means -out points at something this generator
// did not write, and quietly overwriting it — or quietly exempting it from
// the rollback check — would each be a decision made by a missing header
// rather than by a person (CLAUDE.md §3.4, §3.8's "a lookup that cannot
// identify its subject fails closed" applied to a file).
func previousRenderedVersion(path string) (int, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("reading the rendering being replaced at %s: %w", path, err)
	}
	m := renderedVersionPattern.FindSubmatch(data)
	if m == nil {
		return 0, fmt.Errorf("%s exists but carries no \"Rendered from ... (version N)\" header, "+
			"so it is not a rendering this generator wrote and there is no version to check a "+
			"rollback against — move it aside if overwriting it is intended", path)
	}
	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0, fmt.Errorf("parsing the version in %s's header: %w", path, err)
	}
	return v, nil
}

// celIdentifier reduces a key label to something CEL can use as a name.
//
// `attestors.<name>` is an identifier, and a versioned label carries
// hyphens, which an identifier cannot. Digits and letters survive in order,
// so image-signing-key-v1 becomes imagesigningkeyv1 and the mapping is
// obvious to a reader looking at both.
func celIdentifier(label string) string {
	var b strings.Builder
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}
