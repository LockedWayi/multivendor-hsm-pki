// Package keyaudit checks the repository against the key inventory it
// publishes. Signing keys are purpose-separated and verifiers consume the
// inventory. Both are properties of the repository: a workflow line, a
// cosign flag or a manifest label can break them. This check makes them
// mechanical.
//
// It reads configuration and automation only: shell scripts, YAML, JSON,
// Dockerfiles, CI workflows. Not prose and not Go source. Documentation
// has to discuss both key families in one paragraph. A machine told to
// sign with the wrong key is told so in the file types scanned here.
package keyaudit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/inventory"
)

// caKeyLabel matches the CA hierarchy's key labels.
var caKeyLabel = regexp.MustCompile(`ca-(root|intermediate)-key-v[0-9]+`)

// signingKeyLabel matches a supply-chain signing key label under the
// versioned scheme.
var signingKeyLabel = regexp.MustCompile(`(image|artifact|audit|inventory)-signing-key-v[0-9]+`)

// inventorySigningPrefix is the label prefix of the key that signs the
// inventory. It is not an entry in the document it signs: an anchor that
// vouched for itself would be a list anyone holding the key could extend.
// Verifiers hold its public half out of band.
const inventorySigningPrefix = "inventory-signing-key-v"

// Finding is one violation, with enough location to fix it.
type Finding struct {
	Path string
	Line int
	// Rule names which invariant broke.
	Rule string
	Text string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s\n    %s", f.Path, f.Line, f.Rule, strings.TrimSpace(f.Text))
}

// scannedExtensions are the file types that instruct a machine.
var scannedExtensions = map[string]bool{
	".sh": true, ".yaml": true, ".yml": true, ".json": true,
	".bash": true, ".env": true, ".conf": true, ".tf": true,
}

// skippedDirs hold nothing that instructs a machine.
var skippedDirs = map[string]bool{
	".git": true, ".local": true, "vendor": true, "node_modules": true,
}

// Audit walks the repository at root and reports every way its
// configuration contradicts the published inventory. A repository with no
// inventory is a finding: "nothing to check against" must not look like
// "everything checks out".
func Audit(root string) ([]Finding, error) {
	inv, invPath, err := loadInventory(root)
	if err != nil {
		return nil, err
	}

	listed := map[string]bool{}
	for _, e := range inv.Keys {
		listed[e.Label] = true
	}

	var findings []Finding
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !scannedExtensions[filepath.Ext(path)] && !isWorkflow(root, path) && !isDockerfile(d.Name()) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if path == invPath {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		findings = append(findings, auditFile(rel, string(data), listed)...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	findings = append(findings, auditPublishedKeys(root, inv)...)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Line < findings[j].Line
	})
	return findings, nil
}

// auditFile applies the rules to one file. Naming a CA key in
// configuration is fine; the service's config.yaml has to. Naming a
// signing key is fine. Both in one file is the finding: a file that
// configures supply-chain signing and names a CA key is one flag away from
// signing a release with the CA's key. The check is directional, so it
// needs no exemption list.
func auditFile(rel, content string, listed map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")

	signingSurface := false
	for _, line := range lines {
		if strings.Contains(line, "cosign") || signingKeyLabel.MatchString(line) {
			signingSurface = true
			break
		}
	}

	for i, line := range lines {
		lineNo := i + 1

		if signingSurface {
			if m := caKeyLabel.FindString(line); m != "" {
				findings = append(findings, Finding{
					Path: rel, Line: lineNo,
					Rule: fmt.Sprintf("configures supply-chain signing and also names the CA hierarchy key %q; "+
						"a compromised CA key must not be able to sign a release, and the two families meeting in one "+
						"file is how that stops being true", m),
					Text: line,
				})
			}
		}

		for _, label := range signingKeyLabel.FindAllString(line, -1) {
			if strings.HasPrefix(label, inventorySigningPrefix) {
				// The anchor is held out of band, not listed in the
				// document it signs.
				continue
			}
			if !listed[label] {
				findings = append(findings, Finding{
					Path: rel, Line: lineNo,
					Rule: fmt.Sprintf("references signing key %q, which the published inventory does not list; "+
						"a verifier consuming the inventory would reject anything this key signs", label),
					Text: line,
				})
			}
		}
	}
	return findings
}

// auditPublishedKeys checks the exported PEMs against the document. The
// inventory is regenerated from the token and the loose .pub files are
// not, so they drift.
func auditPublishedKeys(root string, inv inventory.Inventory) []Finding {
	var findings []Finding
	for _, e := range inv.Keys {
		path := filepath.Join(root, "docs", "keys", e.Label+".pub")
		rel := filepath.Join("docs", "keys", e.Label+".pub")
		data, err := os.ReadFile(path)
		if err != nil {
			if e.Status == inventory.StatusRetired {
				// A retired key's PEM may have been removed with the key.
				continue
			}
			findings = append(findings, Finding{
				Path: rel, Line: 0,
				Rule: fmt.Sprintf("the inventory lists %q as %s but no exported public key is published for it", e.Label, e.Status),
			})
			continue
		}
		if strings.TrimSpace(string(data)) != strings.TrimSpace(e.PublicKeyPEM) {
			findings = append(findings, Finding{
				Path: rel, Line: 0,
				Rule: fmt.Sprintf("the exported public key for %q differs from the one the inventory publishes; "+
					"a verifier using the loose file and one using the inventory would disagree about the same key", e.Label),
			})
		}
	}
	return findings
}

// VerifyPublishedInventory checks the committed inventory against the
// committed anchor public key. Audit asks whether the repository agrees
// with the document; this asks whether the document is the one the
// offline key signed.
func VerifyPublishedInventory(root string) error {
	document, err := os.ReadFile(filepath.Join(root, "docs", "keys", "key-inventory.json"))
	if err != nil {
		return err
	}
	signature, err := os.ReadFile(filepath.Join(root, "docs", "keys", "key-inventory.json.sig"))
	if err != nil {
		return err
	}
	anchorPEM, err := os.ReadFile(filepath.Join(root, "docs", "keys", "inventory-signing-key-v1.pub"))
	if err != nil {
		return err
	}
	anchor, err := inventory.Entry{Label: "inventory-signing-key-v1", PublicKeyPEM: string(anchorPEM)}.PublicKey()
	if err != nil {
		return err
	}
	return inventory.Verify(document, signature, anchor)
}

func loadInventory(root string) (inventory.Inventory, string, error) {
	path := filepath.Join(root, "docs", "keys", "key-inventory.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return inventory.Inventory{}, "", fmt.Errorf("keyaudit: reading the published inventory: %w", err)
	}
	inv, err := inventory.Parse(data)
	if err != nil {
		return inventory.Inventory{}, "", fmt.Errorf("keyaudit: the published inventory is not valid: %w", err)
	}
	return inv, path, nil
}

// isWorkflow reports whether path is a CI workflow.
func isWorkflow(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return strings.HasPrefix(filepath.ToSlash(rel), ".github/")
}

func isDockerfile(name string) bool {
	return name == "Dockerfile" || strings.HasSuffix(name, ".Dockerfile") || strings.HasPrefix(name, "Dockerfile.")
}
