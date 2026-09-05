// Command token-cleanup removes the test objects a suite run leaves behind
// on a token that persists between runs.
//
// # Why this exists as a separate, operator-run tool
//
// `internal/hsmtest` destroys the objects each run creates, and deliberately
// nothing else: a test suite that deleted objects it did not create would be
// a destructive operation aimed at somebody else's token
// (docs/test-matrix.md §5). That rule is right, and it leaves a real gap —
// a run killed by a timeout, or a cleanup that could not reopen the module,
// leaves objects nobody will ever remove. On a software emulator that is
// untidy. On nShield or Luna hardware, where token memory is finite and
// small, it is the thing that stops the suite being pointable at real
// hardware more than a few times (Phase 7).
//
// So clearing it is an operator's decision, and this is the operator's tool
// for making it. It is not wired into any test.
//
// # Fail-closed by construction
//
// It prints what it would destroy and exits. Nothing is removed without
// -confirm, and even then only objects whose CKA_LABEL matches -prefix,
// which defaults to the run-scoped prefix hsmtest gives every object it
// creates. An empty prefix is refused rather than treated as "everything":
// "delete all test objects" and "delete every key on this token" must not be
// one keystroke apart.
//
// Usage:
//
//	go run ./ci/token-cleanup -module <path> -workspace <label> -pin-env VAR
//	go run ./ci/token-cleanup -module <path> -workspace <label> -pin-env VAR -confirm
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "token-cleanup: "+err.Error())
		os.Exit(1)
	}
}

// object is one candidate for removal, kept with its label so the report
// names what it is about to destroy rather than counting handles.
type object struct {
	handle pk11.ObjectHandle
	class  pk11.ObjectClass
	label  string
}

func run(args []string) error {
	fs := flag.NewFlagSet("token-cleanup", flag.ExitOnError)
	adapterName := fs.String("adapter", config.AdapterSoftHSM2, "vendor adapter: \"softhsm2\" or \"protectserver\"")
	modulePath := fs.String("module", "", "path to the PKCS#11 module (.so)")
	workspaceLabel := fs.String("workspace", "", "token label to clean")
	workspaceSerial := fs.String("workspace-serial", "", "token serial number, to disambiguate when several tokens share the label")
	pinEnv := fs.String("pin-env", "", "environment variable holding the token's PIN")
	prefix := fs.String("prefix", "t-", "destroy only objects whose CKA_LABEL starts with this; hsmtest prefixes every object it creates with \"t-\"")
	confirm := fs.Bool("confirm", false, "actually destroy the objects listed; without it this is a dry run")

	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, v := range map[string]string{
		"-module": *modulePath, "-workspace": *workspaceLabel, "-pin-env": *pinEnv,
	} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	// An empty prefix would mean every object on the token. That may even be
	// what somebody wants one day, but it must not be reachable by leaving a
	// flag off.
	if *prefix == "" {
		return fmt.Errorf("-prefix is empty, which would match every object on the token; " +
			"pass an explicit prefix (hsmtest uses \"t-\")")
	}

	adapter, err := newAdapter(*adapterName, *modulePath)
	if err != nil {
		return err
	}
	defer adapter.Close()

	ctx := context.Background()
	ws, err := findWorkspace(ctx, adapter, *workspaceLabel, *workspaceSerial)
	if err != nil {
		return err
	}

	pin := os.Getenv(*pinEnv)
	if pin == "" {
		return fmt.Errorf("environment variable %s is not set", *pinEnv)
	}
	if err := adapter.LoginToken(ctx, ws, []byte(pin), pk11.RoleUser); err != nil {
		return fmt.Errorf("logging into %q: %w", ws.Label, err)
	}
	defer func() { _ = adapter.LogoutToken(ctx) }()

	s, err := adapter.OpenSession(ctx, ws, pk11.DefaultSessionOptions())
	if err != nil {
		return fmt.Errorf("opening a session on %q: %w", ws.Label, err)
	}
	defer func() { _ = adapter.CloseSession(ctx, s) }()

	all, matched, err := survey(ctx, adapter, s, *prefix)
	if err != nil {
		return err
	}

	fmt.Printf("token %q (serial %s)\n", ws.Label, ws.Serial)
	fmt.Printf("  %d key objects total, %d matching prefix %q\n", all, len(matched), *prefix)
	printByRun(matched)

	if len(matched) == 0 {
		return nil
	}
	if !*confirm {
		fmt.Printf("\ndry run — nothing was destroyed. Re-run with -confirm to remove these %d objects.\n", len(matched))
		return nil
	}

	var failures int
	for _, o := range matched {
		if err := adapter.DestroyObject(ctx, s, o.handle); err != nil {
			// Reported and carried on rather than aborting: stopping at the
			// first failure would leave the operator to work out which half
			// of the list is gone.
			fmt.Fprintf(os.Stderr, "  failed to destroy %q (class %d): %v\n", o.label, o.class, err)
			failures++
		}
	}
	fmt.Printf("\ndestroyed %d objects, %d failures\n", len(matched)-failures, failures)
	if failures > 0 {
		return fmt.Errorf("%d objects could not be destroyed", failures)
	}
	return nil
}

// survey lists every public and private key object on the token and returns
// the total count alongside those matching prefix.
//
// Both counts are reported because the ratio is the useful number: "42 of
// 2048" tells an operator this is litter, "2048 of 2048" tells them to stop
// and read the prefix again.
func survey(ctx context.Context, adapter pk11.VendorAdapter, s *pk11.Session, prefix string) (total int, matched []object, err error) {
	for _, class := range []pk11.ObjectClass{pk11.ClassPublicKey, pk11.ClassPrivateKey} {
		handles, err := adapter.FindObjects(ctx, s, []pk11.Attribute{
			pk11.NumericAttribute(pk11.AttrClass, uint64(class)),
		})
		if err != nil {
			return 0, nil, fmt.Errorf("listing objects of class %d: %w", class, err)
		}
		total += len(handles)
		for _, h := range handles {
			attrs, err := adapter.GetAttributes(ctx, s, h, []pk11.AttributeType{pk11.AttrLabel})
			if err != nil {
				// An object whose label cannot be read is one this tool
				// cannot claim to have identified, so it is left alone.
				continue
			}
			for _, a := range attrs {
				if a.Type == pk11.AttrLabel && strings.HasPrefix(string(a.Value), prefix) {
					matched = append(matched, object{handle: h, class: class, label: string(a.Value)})
				}
			}
		}
	}
	return total, matched, nil
}

// printByRun groups the matched objects by the run id embedded in their
// label, so an operator can see whether this is one abandoned run or a
// year of them before agreeing to delete anything.
func printByRun(matched []object) {
	if len(matched) == 0 {
		return
	}
	byRun := map[string]int{}
	for _, o := range matched {
		parts := strings.SplitN(o.label, "-", 3)
		run := o.label
		if len(parts) >= 2 {
			run = parts[0] + "-" + parts[1]
		}
		byRun[run]++
	}
	runs := make([]string, 0, len(byRun))
	for r := range byRun {
		runs = append(runs, r)
	}
	sort.Strings(runs)
	for _, r := range runs {
		fmt.Printf("    %-28s %d objects\n", r, byRun[r])
	}
}

func newAdapter(adapterName, modulePath string) (pk11.VendorAdapter, error) {
	switch adapterName {
	case config.AdapterSoftHSM2:
		return pk11.NewSoftHSM2Adapter(modulePath)
	case config.AdapterProtectServer:
		return pk11.NewProtectServerAdapter(modulePath)
	default:
		return nil, fmt.Errorf("unknown -adapter %q", adapterName)
	}
}

// findWorkspace resolves a token by label, refusing to guess when the label
// matches more than one — the same rule the rest of the platform applies
// . It matters more here than usual: picking the wrong
// token would mean destroying objects on it.
func findWorkspace(ctx context.Context, adapter pk11.VendorAdapter, label, serial string) (pk11.Workspace, error) {
	workspaces, err := adapter.Workspaces(ctx)
	if err != nil {
		return pk11.Workspace{}, err
	}
	var matches []pk11.Workspace
	for _, w := range workspaces {
		if w.Label != label {
			continue
		}
		if serial != "" && w.Serial != serial {
			continue
		}
		matches = append(matches, w)
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return pk11.Workspace{}, fmt.Errorf("token %q not found", label)
	default:
		var b strings.Builder
		for _, w := range matches {
			fmt.Fprintf(&b, "\n  serial %q (slot %d)", w.Serial, w.SlotID)
		}
		return pk11.Workspace{}, fmt.Errorf("label %q matches %d tokens — refusing to guess which one to clean; "+
			"re-run with -workspace-serial. Candidates:%s", label, len(matches), b.String())
	}
}
