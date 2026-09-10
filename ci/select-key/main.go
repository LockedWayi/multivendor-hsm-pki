// Command select-key prints the keys a verifier or a signer may use for one
// purpose at one point in time, read from a key inventory.
//
// The policy generator and the shell verifiers used to select keys with
// separate code. The shell copies did not check valid_until, valid_from or
// retired_at. This command is the one selection every consumer calls.
//
//	go run ./ci/select-key -inventory docs/keys/key-inventory.json -purpose image
//	go run ./ci/select-key ... -at 2027-01-01T00:00:00Z -out-dir .local/verify
//
// Output is one line per selected key, tab separated: label, status, and
// the path of the PEM file written under -out-dir, or "-" when no directory
// was given. The exit status is 1 when the inventory is invalid, expired,
// or lists no usable key for the purpose.
//
// The signature over the inventory is not checked here. The caller checks
// it with openssl before calling this command.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/inventory"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "select-key: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("select-key", flag.ContinueOnError)
	fs.SetOutput(out)
	invPath := fs.String("inventory", "docs/keys/key-inventory.json", "path to the key inventory")
	purpose := fs.String("purpose", "", "key purpose: image or artifact")
	at := fs.String("at", "", "the point in time to select for, RFC 3339; defaults to now")
	outDir := fs.String("out-dir", "", "write each selected key as <label>.pub in this directory")
	activeOnly := fs.Bool("active-only", false, "select keys a signer may use, not keys a verifier may accept")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *purpose == "" {
		return errors.New("-purpose is required")
	}
	if *at != "" {
		parsed, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return fmt.Errorf("-at %q is not RFC 3339: %w", *at, err)
		}
		now = parsed
	}

	raw, err := os.ReadFile(filepath.Clean(*invPath))
	if err != nil {
		return fmt.Errorf("reading the inventory: %w", err)
	}
	inv, err := inventory.Parse(raw)
	if err != nil {
		return err
	}

	p := inventory.Purpose(*purpose)
	var selected []inventory.Entry
	if *activeOnly {
		selected, err = inv.ActiveAt(p, now)
	} else {
		selected, err = inv.VerifiableAt(p, now)
	}
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		return fmt.Errorf("the inventory lists no usable %s key at %s", p, now.Format(time.RFC3339))
	}

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", *outDir, err)
		}
	}
	for _, e := range selected {
		path := "-"
		if *outDir != "" {
			path = filepath.Join(*outDir, e.Label+".pub")
			if err := os.WriteFile(path, []byte(e.PublicKeyPEM), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", path, err)
			}
		}
		fmt.Fprintf(out, "%s\t%s\t%s\n", e.Label, e.Status, path)
	}
	return nil
}
