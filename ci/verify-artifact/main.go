// Command verify-artifact checks a cosign signature bundle against a
// published public key, using nothing but the Go standard library.
//
// # Why a second verifier exists at all
//
// cosign can verify its own output, and Phase 4.9 confirms that it does.
// But a signature checked only by the tool that produced it proves the tool
// agrees with itself, which it would do just as convincingly if the whole
// encoding were wrong -- this repository has shipped that exact defect
// twice, and independent verification is the rule that
// came out of it. So the release gate is this program, and cosign's own
// verify is the cross-check rather than the other way round.
//
// There is a second, blunter reason. cosign v3 verifies a keyed bundle only
// with --insecure-ignore-tlog, because its default trust model expects a
// transparency log entry that a private, key-based signature does not have
// and does not need. A verification recipe whose first instruction is a flag
// named "insecure", printing a warning that the reader is doing something
// unsafe, is a recipe nobody follows correctly. This program says yes or no.
//
// # Fail closed
//
// Exit status is the whole interface: 0 only when the bundle names this key,
// the digest it carries is the digest of the bytes actually supplied, and
// the signature verifies over them. Every other outcome -- including a
// bundle this program does not recognise -- is non-zero.
//
// Usage:
//
//	go run ./ci/verify-artifact -key docs/keys/artifact-signing-key-v1.pub \
//	    -bundle release/hsm-pki-server.bundle release/hsm-pki-server
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/LockedWayi/hsm-pki-platform/internal/artifactsig"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "verify-artifact: %v\n", err)
		os.Exit(1)
	}
}

// run takes its arguments and its output explicitly so the gate can be
// tested. A security check whose only caller is main() is a check nobody
// can point a test at.
func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify-artifact", flag.ContinueOnError)
	fs.SetOutput(out)
	keyPath := fs.String("key", "", "path to the signer's PKIX PEM public key")
	bundlePath := fs.String("bundle", "", "path to the cosign signature bundle")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *keyPath == "" || *bundlePath == "" || fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("need -key, -bundle and exactly one artifact path")
	}
	artifactPath := fs.Arg(0)

	keyPEM, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}
	pub, err := artifactsig.PublicKeyFromPEM(keyPEM)
	if err != nil {
		return err
	}

	bundleData, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fmt.Errorf("reading bundle: %w", err)
	}
	bundle, err := artifactsig.Parse(bundleData)
	if err != nil {
		return err
	}

	// Streamed rather than read whole: a release artifact is a container
	// image or a binary, and holding it in memory to hash it is a cost with
	// no purpose.
	artifact, err := os.Open(artifactPath)
	if err != nil {
		return fmt.Errorf("opening artifact: %w", err)
	}
	defer artifact.Close()

	if err := artifactsig.Verify(bundle, artifact, pub); err != nil {
		return err
	}
	fmt.Fprintf(out, "verified: %s\n  signed by the key published at %s\n", artifactPath, *keyPath)
	return nil
}
