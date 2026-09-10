// Command verify-artifact checks a cosign signature bundle against a
// published public key, using the Go standard library only. cosign can
// verify its own output; that shows cosign agrees with itself. This
// program is the gate, and cosign's own verify is the cross-check.
//
// cosign v3 verifies a keyed bundle only with --insecure-ignore-tlog,
// because its default trust model expects a transparency log entry. A
// verification recipe whose first flag is named "insecure" is not one
// people follow. This program answers yes or no.
//
// Exit status is the whole interface: 0 only when the bundle names this
// key, the digest it carries is the digest of the bytes supplied, and the
// signature verifies over them. Everything else, including a bundle this
// program does not recognise, is non-zero.
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

	"github.com/LockedWayi/multivendor-hsm-pki/internal/artifactsig"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "verify-artifact: %v\n", err)
		os.Exit(1)
	}
}

// run takes its arguments and output explicitly so the gate can be tested.
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

	// Streamed: a release artifact can be large.
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
