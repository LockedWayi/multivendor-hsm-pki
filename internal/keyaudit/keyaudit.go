// Package keyaudit checks the repository against the key inventory it
// publishes (Phase 4.8).
//
// # What this is for
//
// CLAUDE.md §3.6 says signing keys are purpose-separated and never
// interchangeable, and §3.7 says verifiers consume the inventory rather than
// a hard-coded key. Both are properties of the *repository*, not of any one
// function: they are broken by a line in a workflow file, a cosign flag in a
// script, or a key label in a Kubernetes manifest. A rule that only a
// careful reader can enforce is a rule that lasts until the first hurried
// afternoon, so this makes the two mechanical.
//
// # What it looks at, and what it deliberately does not
//
// Configuration and automation only: shell scripts, YAML, JSON, Dockerfiles,
// CI workflows. Not prose and not Go source. Documentation has to be able to
// discuss the CA keys and the signing keys in the same paragraph — that is
// what documentation is for — and a check that forbade it would be
// answered by writing worse documentation. What must never happen is a
// *machine* being told to sign with the wrong key, and a machine is told
// that in exactly the file types scanned here.
package keyaudit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/LockedWayi/hsm-pki-platform/internal/inventory"
)

// caKeyLabel matches the CA hierarchy's key labels.
var caKeyLabel = regexp.MustCompile(`ca-(root|intermediate)-key-v[0-9]+`)

// signingKeyLabel matches a supply-chain signing key label under the
// versioned scheme (CLAUDE.md §3.7).
var signingKeyLabel = regexp.MustCompile(`(image|artifact|audit|inventory)-signing-key-v[0-9]+`)

// InventorySigningKeyLabel is the label prefix of the key that signs the
// inventory. It is deliberately *not* an entry in the document it signs: an
// anchor that vouched for itself would be a list anyone holding the key
// could extend. Verifiers pin its public half out of band instead, the way
// TUF bootstraps `root.json`.
const inventorySigningPrefix = "inventory-signing-key-v"

// Finding is one violation, with enough location to fix it.
type Finding struct {
	Path string
	Line int
	// Rule names which invariant broke, so a failure reads as a statement
	// about the platform rather than as a grep result.
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

// skippedDirs are not part of the repository's instructions to a machine:
// .git is history, .local is a developer's throwaway token state, and
// docs/keys holds the published artifacts this check compares *against*.
var skippedDirs = map[string]bool{
	".git": true, ".local": true, "vendor": true, "node_modules": true,
}

// Audit walks the repository at root and reports every way its
// configuration contradicts the published inventory.
//
// The inventory is read from docs/keys/key-inventory.json. A repository with
// no inventory is a finding in itself rather than a pass: "nothing to check
// against" and "everything checks out" must not look the same (CLAUDE.md
// §3.4).
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

// auditFile applies the rules to one file.
//
// # The rule is that the two key families never meet in one file
//
// Naming a CA key in configuration is not itself wrong — the CA service's
// own config.yaml has to name the intermediate it signs with, and the
// ceremony script has to name the keys it creates. Naming a signing key is
// not wrong either. What is wrong is *both in one place*, because a file
// that configures supply-chain signing and also names a CA key is one flag
// away from signing a release with the CA's key, and that is the blast
// radius CLAUDE.md §3.6 exists to bound.
//
// So the check is directional and needs no exemption list. An earlier
// version flagged every CA label anywhere and had to carve out the ceremony
// by filename; it also flagged the service's own config, which is the one
// file that *must* name that key. An exemption list is a rule the next
// person edits instead of obeys.
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
						"file is how that stops being true (CLAUDE.md §3.6)", m),
					Text: line,
				})
			}
		}

		for _, label := range signingKeyLabel.FindAllString(line, -1) {
			if strings.HasPrefix(label, inventorySigningPrefix) {
				// The anchor is pinned out of band, not listed in the
				// document it signs. See inventorySigningPrefix.
				continue
			}
			if !listed[label] {
				findings = append(findings, Finding{
					Path: rel, Line: lineNo,
					Rule: fmt.Sprintf("references signing key %q, which the published inventory does not list; "+
						"a verifier consuming the inventory would reject anything this key signs (CLAUDE.md §3.7)", label),
					Text: line,
				})
			}
		}
	}
	return findings
}

// auditPublishedKeys checks the exported PEMs against the document.
//
// They drift silently otherwise: the inventory is regenerated from the
// token, the loose `.pub` files are not, and a verifier handed the wrong one
// gets "signature does not verify" with nothing pointing at why.
func auditPublishedKeys(root string, inv inventory.Inventory) []Finding {
	var findings []Finding
	for _, e := range inv.Keys {
		path := filepath.Join(root, "docs", "keys", e.Label+".pub")
		rel := filepath.Join("docs", "keys", e.Label+".pub")
		data, err := os.ReadFile(path)
		if err != nil {
			if e.Status == inventory.StatusRetired {
				// A retired key's PEM may legitimately have been removed
				// with the key; the inventory entry is the record.
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
// committed anchor public key.
//
// Separate from Audit because it answers a different question: Audit asks
// whether the repository's instructions agree with the document, this asks
// whether the document is the one the offline key actually signed.
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

// isWorkflow reports whether path is a CI workflow, which carries no
// extension convention this check can rely on beyond its directory.
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
