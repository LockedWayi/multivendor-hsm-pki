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
	"strings"

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
	Attestors    []attestor
	ExcludedNS   []string
	Insecure     bool
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	raw, err := os.ReadFile(filepath.Clean(*invPath))
	if err != nil {
		return fmt.Errorf("reading the inventory: %w", err)
	}
	inv, err := inventory.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing the inventory: %w", err)
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

	var expressions []string
	for _, list := range []string{"containers", "initContainers", "ephemeralContainers"} {
		expressions = append(expressions, list)
	}

	var buf bytes.Buffer
	if err := policyTemplate.Execute(&buf, struct {
		policyData
		Lists []string
	}{
		policyData: policyData{
			Source:       *invPath,
			InventoryVer: inv.Version,
			Attestors:    attestors,
			ExcludedNS:   []string{"kube-system", "kube-public", "kube-node-lease", "kyverno"},
			Insecure:     *insecure,
		},
		Lists: expressions,
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
