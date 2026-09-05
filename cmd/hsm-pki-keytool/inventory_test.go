package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LockedWayi/hsm-pki-platform/internal/hsmtest"
	"github.com/LockedWayi/hsm-pki-platform/internal/inventory"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
	"github.com/LockedWayi/hsm-pki-platform/internal/signingkey"
)

// provisionOn generates one signing key on ws and returns its public PEM.
//
// Login and logout bracket each call rather than wrapping the whole setup,
// because PKCS#11 authenticates a token for the whole application: holding
// one token authenticated while logging into another is exactly what
// LoginToken refuses, and the tokens here are deliberately two.
func provisionOn(t *testing.T, b *hsmtest.Backend, ws pk11.Workspace, pin, label string) []byte {
	t.Helper()
	ctx := context.Background()

	s, err := b.Adapter.OpenSession(ctx, ws, pk11.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession(%s): %v", ws.Label, err)
	}
	defer func() { _ = b.Adapter.CloseSession(ctx, s) }()
	if err := b.Adapter.Login(ctx, s, []byte(pin), pk11.RoleUser); err != nil {
		t.Fatalf("Login(%s): %v", ws.Label, err)
	}
	defer func() { _ = b.Adapter.LogoutToken(ctx) }()

	key, err := signingkey.Provision(ctx, b.Adapter, s, signingkey.Params{Label: label})
	if err != nil {
		t.Fatalf("Provision(%s on %s): %v", label, ws.Label, err)
	}
	pemBytes, err := key.PEM()
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	return pemBytes
}

// inventoryFixture provisions the two supply-chain keys on the primary
// token and the inventory signing key on the secondary, then hands back the
// labels and a ready flag set. It releases the module afterwards, because
// the command opens its own adapter.
type inventoryFixture struct {
	dir           string
	imageLabel    string
	imageLabelV2  string
	artifactLabel string
	invKeyLabel   string
	invKeyPEM     []byte
	args          []string
}

func newInventoryFixture(t *testing.T, b *hsmtest.Backend) inventoryFixture {
	t.Helper()
	f := inventoryFixture{
		dir:           t.TempDir(),
		imageLabel:    b.Label("image-signing-key-v1"),
		imageLabelV2:  b.Label("image-signing-key-v2"),
		artifactLabel: b.Label("artifact-signing-key-v1"),
		invKeyLabel:   b.Label("inventory-signing-key-v1"),
	}

	// Every key here is generated through the *same* adapter instance, and
	// that is load-bearing rather than incidental. ProtectToolkit-C 7.3.3 in
	// software emulation seeds its RNG per C_Initialize, so the first key
	// generated after each library initialisation is the same key every
	// time. A fixture that opened a second
	// adapter to make v2 would get v1's key back, and the failure would
	// look like a bug in the inventory rather than what it is.
	provisionOn(t, b, b.Primary, b.PrimaryPIN, f.imageLabel)
	provisionOn(t, b, b.Primary, b.PrimaryPIN, f.imageLabelV2)
	provisionOn(t, b, b.Primary, b.PrimaryPIN, f.artifactLabel)
	f.invKeyPEM = provisionOn(t, b, b.Secondary, b.SecondaryPIN, f.invKeyLabel)

	const keyPINEnv, invPINEnv = "KEYTOOL_TEST_SUPPLY_PIN", "KEYTOOL_TEST_INVENTORY_PIN"
	t.Setenv(keyPINEnv, b.PrimaryPIN)
	t.Setenv(invPINEnv, b.SecondaryPIN)
	b.Release()

	f.args = []string{
		"-adapter", b.AdapterName,
		"-module", b.ModulePath,
		"-workspace", b.Primary.Label,
		"-pin-env", keyPINEnv,
		"-inventory-workspace", b.Secondary.Label,
		"-inventory-pin-env", invPINEnv,
		"-inventory-key-label", f.invKeyLabel,
		"-key", "image:" + f.imageLabel + ":active",
		"-key", "artifact:" + f.artifactLabel + ":active",
		"-out", filepath.Join(f.dir, "key-inventory.json"),
		"-signature-out", filepath.Join(f.dir, "key-inventory.json.sig"),
	}
	return f
}

func (f inventoryFixture) documentPath() string { return filepath.Join(f.dir, "key-inventory.json") }
func (f inventoryFixture) signaturePath() string {
	return filepath.Join(f.dir, "key-inventory.json.sig")
}

// TestRunGenerateInventoryCmd_ProducesADocumentOpenSSLAccepts is the
// end-to-end claim: a signature made by a key that never left an HSM, over
// a document a foreign implementation can read and check with the recipe
// this repository publishes. Verifying it with our own
// inventory.Verify would prove only that the package agrees with itself.
func TestRunGenerateInventoryCmd_ProducesADocumentOpenSSLAccepts(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		f := newInventoryFixture(t, b)

		if err := runGenerateInventoryCmd(f.args); err != nil {
			t.Fatalf("runGenerateInventoryCmd: %v", err)
		}

		document, err := os.ReadFile(f.documentPath())
		if err != nil {
			t.Fatalf("reading the document: %v", err)
		}
		inv, err := inventory.Parse(document)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if inv.Version != 1 {
			t.Errorf("version = %d, want 1 for a first generation", inv.Version)
		}
		if got := inv.Active(inventory.PurposeImage); len(got) != 1 || got[0].Label != f.imageLabel {
			t.Errorf("Active(image) = %+v, want just %s", got, f.imageLabel)
		}
		if got := inv.Active(inventory.PurposeArtifact); len(got) != 1 || got[0].Label != f.artifactLabel {
			t.Errorf("Active(artifact) = %+v, want just %s", got, f.artifactLabel)
		}
		// No private material anywhere in a document that gets published.
		if strings.Contains(string(document), "PRIVATE") {
			t.Error("the inventory mentions PRIVATE")
		}

		openssl, err := exec.LookPath("openssl")
		if err != nil {
			t.Skip("openssl not installed; the parse assertions above still ran")
		}
		pubPath := filepath.Join(f.dir, "inventory-signing-key.pub")
		if err := os.WriteFile(pubPath, f.invKeyPEM, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		out, err := exec.Command(openssl, "dgst", "-sha256", "-verify", pubPath,
			"-signature", f.signaturePath(), f.documentPath()).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Verified OK") {
			t.Fatalf("openssl rejected an HSM-made inventory signature: %v\n%s", err, out)
		}

		// And it must reject a changed document, or the check above only
		// proves openssl says yes to whatever it is handed.
		tampered := append([]byte(nil), document...)
		tampered[len(tampered)/2] ^= 0x01
		bad := filepath.Join(f.dir, "tampered.json")
		if err := os.WriteFile(bad, tampered, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if out, err := exec.Command(openssl, "dgst", "-sha256", "-verify", pubPath,
			"-signature", f.signaturePath(), bad).CombinedOutput(); err == nil {
			t.Fatalf("openssl accepted a tampered inventory: %s", out)
		}
	})
}

// TestRunGenerateInventoryCmd_RefusesOneTokenForBoth is the security
// property the whole document rests on. A list of trusted keys signed by a
// key on the same token authorises whoever holds that token to add their
// own key — so the two tokens have to actually be two, measured by serial
// rather than by the label an operator typed.
func TestRunGenerateInventoryCmd_RefusesOneTokenForBoth(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		f := newInventoryFixture(t, b)
		args := replaceFlag(f.args, "-inventory-workspace", b.Primary.Label)

		err := runGenerateInventoryCmd(args)
		if err == nil {
			t.Fatal("generating an inventory signed by a key on the token it lists succeeded, want an error")
		}
		if !strings.Contains(err.Error(), "one token") {
			t.Fatalf("error = %v, want it to say the two tokens are one", err)
		}
		if _, statErr := os.Stat(f.documentPath()); !os.IsNotExist(statErr) {
			t.Error("a document was written despite the refusal")
		}
	})
}

// TestRunGenerateInventoryCmd_RefusesToOverwriteWithoutTheCurrentDocument
// protects the two fields that only exist in the previous file: the version
// counter and every valid_from. Regenerating without reading it would reset
// both, which silently turns a rotation into a rollback.
func TestRunGenerateInventoryCmd_RefusesToOverwriteWithoutTheCurrentDocument(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		f := newInventoryFixture(t, b)
		if err := runGenerateInventoryCmd(f.args); err != nil {
			t.Fatalf("first generation: %v", err)
		}
		first, err := os.ReadFile(f.documentPath())
		if err != nil {
			t.Fatalf("reading the document: %v", err)
		}

		if err := runGenerateInventoryCmd(f.args); err == nil {
			t.Fatal("regenerating over an existing document without -in succeeded, want an error")
		}
		second, err := os.ReadFile(f.documentPath())
		if err != nil {
			t.Fatalf("reading the document: %v", err)
		}
		if string(first) != string(second) {
			t.Error("the existing document was modified despite the refusal")
		}
	})
}

// TestRunGenerateInventoryCmd_RotationBumpsVersionAndKeepsHistory walks the
// lifecycle the key lifecycle describes: a new version arrives active, the
// previous one becomes verify-only, and signatures it already made keep
// verifying. The version counter has to advance, or a verifier cannot tell
// a rollback from an update.
func TestRunGenerateInventoryCmd_RotationBumpsVersionAndKeepsHistory(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		f := newInventoryFixture(t, b)
		if err := runGenerateInventoryCmd(f.args); err != nil {
			t.Fatalf("first generation: %v", err)
		}
		before, err := inventory.Parse(mustRead(t, f.documentPath()))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}

		// Rotate the image key: v2 is already on the token (the fixture
		// made it), so this is the inventory half of the lifecycle — v1
		// becomes verify-only, v2 becomes active.
		v2 := f.imageLabelV2
		args := replaceFlag(f.args, "-key", "image:"+f.imageLabel+":verify-only")
		args = append(args, "-key", "image:"+v2+":active", "-in", f.documentPath())
		if err := runGenerateInventoryCmd(args); err != nil {
			t.Fatalf("regeneration: %v", err)
		}

		after, err := inventory.Parse(mustRead(t, f.documentPath()))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if after.Version != before.Version+1 {
			t.Errorf("version = %d, want %d", after.Version, before.Version+1)
		}
		// The new version signs; the old one only verifies. That gap is
		// the entire reason a verifier reads a list rather than a key.
		if got := after.Active(inventory.PurposeImage); len(got) != 1 || got[0].Label != v2 {
			t.Errorf("Active(image) = %+v, want just %s", got, v2)
		}
		if got := after.Verifiable(inventory.PurposeImage); len(got) != 2 {
			t.Errorf("Verifiable(image) = %d entries, want 2 (v1 verify-only and v2 active)", len(got))
		}
		// valid_from is a historical fact and must survive regeneration,
		// or every key looks as though it were provisioned today.
		for _, e := range after.Keys {
			if e.Label != f.imageLabel {
				continue
			}
			var wanted bool
			for _, old := range before.Keys {
				if old.Label == e.Label && old.ValidFrom.Equal(e.ValidFrom) {
					wanted = true
				}
			}
			if !wanted {
				t.Errorf("%s: valid_from was rewritten on regeneration", e.Label)
			}
		}
	})
}

// TestRunGenerateInventoryCmd_RefusesToCallALiveKeyRetired is the check
// that keeps the document from asserting something about the token that is
// not true. "Retired" means destroyed on the token;
// publishing the claim while the private key is still there would make the
// inventory a statement nobody measured.
func TestRunGenerateInventoryCmd_RefusesToCallALiveKeyRetired(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		f := newInventoryFixture(t, b)
		if err := runGenerateInventoryCmd(f.args); err != nil {
			t.Fatalf("first generation: %v", err)
		}

		args := replaceFlag(f.args, "-key", "image:"+f.imageLabel+":retired")
		args = append(args, "-in", f.documentPath())

		err := runGenerateInventoryCmd(args)
		if err == nil {
			t.Fatal("marking a key retired while it is still on the token succeeded, want an error")
		}
		if !strings.Contains(err.Error(), "still on token") {
			t.Fatalf("error = %v, want it to say the key is still on the token", err)
		}
	})
}

// TestRunGenerateInventoryCmd_RefusesARetiredKeyItHasNeverSeen covers the
// other half: a retired key's public half can only come from the document
// that listed it while it existed, because the key itself is gone.
func TestRunGenerateInventoryCmd_RefusesARetiredKeyItHasNeverSeen(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		f := newInventoryFixture(t, b)
		if err := runGenerateInventoryCmd(f.args); err != nil {
			t.Fatalf("first generation: %v", err)
		}

		args := append(append([]string(nil), f.args...),
			"-key", "image:"+b.Label("image-signing-key-v0")+":retired",
			"-in", f.documentPath())

		if err := runGenerateInventoryCmd(args); err == nil {
			t.Fatal("listing a retired key absent from the current inventory succeeded, want an error")
		}
	})
}

// --- pure logic below: no token, so these do not multiply per backend ---

func TestKeySpecs_Set(t *testing.T) {
	var k keySpecs
	if err := k.Set("image:image-signing-key-v1:active"); err != nil {
		t.Fatalf("Set on a well-formed spec: %v", err)
	}
	if len(k) != 1 || k[0].purpose != inventory.PurposeImage || k[0].status != inventory.StatusActive {
		t.Fatalf("parsed spec = %+v", k)
	}
	// A status this tool defaulted would be a lifecycle decision made by a
	// default value, so an incomplete spec is refused rather than filled in.
	for _, bad := range []string{"image:image-signing-key-v1", "image::active", ":label:active", "image:label:active:extra", ""} {
		var k keySpecs
		if err := k.Set(bad); err == nil {
			t.Errorf("Set(%q) = nil, want an error", bad)
		}
	}
}

func TestRun_RoutesTheGenerateInventorySubcommand(t *testing.T) {
	err := run([]string{"generate-inventory"})
	if err == nil {
		t.Fatal("run(generate-inventory) with no flags succeeded, want an error")
	}
	if strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("generate-inventory is not routed by run: %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}

// replaceFlag returns args with the first occurrence of name's value
// replaced, so a test can change one thing about a valid flag set.
func replaceFlag(args []string, name, value string) []string {
	out := append([]string(nil), args...)
	for i, a := range out {
		if a == name {
			out[i+1] = value
			return out
		}
	}
	return out
}
