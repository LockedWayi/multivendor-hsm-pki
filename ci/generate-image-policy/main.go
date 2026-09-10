// Command generate-image-policy renders the admission policy that decides
// which container images may run, from the published key inventory.
//
// A policy with a public key pasted into it is a hard-coded verifier. On
// the day image-signing-key-v1 is rotated, images signed by v2 would be
// refused until somebody remembered this file. So the policy holds every
// key the inventory lists as active or verify-only for the image purpose,
// and a rotation is a regeneration.
//
// It emits two objects: an ImageValidatingPolicy, require-signed-images,
// and a ValidatingPolicy, require-image-digest. The second matters: a
// signature is over a digest, and a tag-named image can be repointed after
// admission approved it.
//
// The inventory is verified before it is believed. The generator's output
// is what the cluster trusts, so it refuses an inventory whose detached
// signature does not verify against the anchor, an expired inventory, and
// an inventory older than the one its existing rendering came from.
//
// Usage:
//
//	go run ./ci/generate-image-policy -out deploy/k8s/policy/image-signature.yaml
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/inventory"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "generate-image-policy: %v\n", err)
		os.Exit(1)
	}
}

// attestor is one trusted key, as the policy template needs it.
type attestor struct {
	// Name is a CEL identifier: the label with everything CEL cannot carry
	// removed.
	Name string
	// Label and Status are written into the output as a comment.
	Label  string
	Status string
	PEM    string
}

type policyData struct {
	Source       string
	InventoryVer int
	// Anchor and ValidUntil are written into the rendered file's header, so
	// a reader sees what the document was checked against.
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
	// Off by default. A policy that fetches signatures over plaintext
	// cannot tell the registry from anyone answering on its address. The
	// dev overlay renders its own copy with this on for the k3d registry.
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

	// The signature is checked before the document is parsed, so a tampered
	// file is reported as such. The defaults resolve beside the inventory.
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
		return fmt.Errorf("reading the inventory's signature: %w; an inventory without its "+
			"signature is a list of trusted keys anyone could have written. Pass -signature "+
			"if it lives somewhere other than beside the inventory", err)
	}
	anchorPEM, err := os.ReadFile(filepath.Clean(resolvedAnchor))
	if err != nil {
		return fmt.Errorf("reading the inventory signing anchor: %w; pass -anchor if it "+
			"lives somewhere other than beside the inventory", err)
	}
	anchor, err := inventory.Entry{Label: filepath.Base(resolvedAnchor), PublicKeyPEM: string(anchorPEM)}.PublicKey()
	if err != nil {
		return fmt.Errorf("parsing the anchor %s: %w", resolvedAnchor, err)
	}
	if err := inventory.Verify(raw, sig, anchor); err != nil {
		return fmt.Errorf("the inventory's signature does not verify against %s: %w. "+
			"A policy rendered from an unverified inventory would let whoever edited the "+
			"file choose which keys the cluster trusts", resolvedAnchor, err)
	}

	inv, err := inventory.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing the inventory: %w", err)
	}

	// Freshness and key selection share one implementation with every
	// other consumer: an expired document is refused, a not-yet-valid key
	// is left out, a retired key is never included.
	verifiable, err := inv.VerifiableAt(inventory.PurposeImage, time.Now())
	if errors.Is(err, inventory.ErrExpired) {
		return fmt.Errorf("%v. A stale list of trusted keys is refused rather than rendered. "+
			"Regenerate and re-sign it with hsm-pki-keytool generate-inventory", err)
	}
	if err != nil {
		return err
	}

	// An older inventory can resurrect a retired key. The floor is read
	// from the -out file's own header. Stdout mode replaces nothing.
	if *outPath != "" {
		prev, err := previousRenderedVersion(*outPath)
		if err != nil {
			return err
		}
		if prev > 0 && inv.Version < prev {
			return fmt.Errorf("the inventory is version %d but %s was rendered from version %d: "+
				"refusing the rollback; an older list can resurrect a retired key. If replacing "+
				"the rendering with an older inventory is intended, move the existing "+
				"file aside first", inv.Version, *outPath, prev)
		}
	}

	if len(verifiable) == 0 {
		// A policy with no attestors refuses every image and reads as a
		// broken policy rather than an empty inventory.
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
		// Two labels collapsing to one identifier would drop a key.
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

	// Every list a pod can carry an image in, enumerated so a new one is a
	// change somebody makes.
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

// renderedVersionPattern matches the header line every rendering carries,
// which is where the rollback floor comes from.
var renderedVersionPattern = regexp.MustCompile(`Rendered from .+ \(version ([0-9]+)\)`)

// previousRenderedVersion reads the inventory version out of the rendering
// being replaced, or 0 when no file exists. A file with no version header
// is refused: -out then points at something this generator did not write.
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
			"rollback against; move it aside if overwriting it is intended", path)
	}
	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0, fmt.Errorf("parsing the version in %s's header: %w", path, err)
	}
	return v, nil
}

// celIdentifier reduces a key label to a CEL identifier: letters and
// digits survive in order, so image-signing-key-v1 becomes
// imagesigningkeyv1.
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
