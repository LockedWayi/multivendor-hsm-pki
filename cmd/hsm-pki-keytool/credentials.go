package main

// The two credentials the authenticated listener needs before it can do
// anything: the service's own TLS identity, and the first client
// certificate an operator authenticates with.
//
// Both are minted here rather than over the API, and that is the whole
// point. The write endpoints accept only a client certificate this CA
// issued, so the API that would issue the first one is the API that
// client certificate exists to open. Something outside the service has to
// break the circle. The alternatives were weighed and rejected in the
// phase record: a bootstrap mode on first start is a window that is open
// whenever the service restarts, and a certificate minted at the root's
// ceremony brings the root out of its safe to sign a leaf, which is the
// one thing the two-tier hierarchy exists to prevent.
//
// Three properties these commands share, each of them load-bearing:
//
//   - They issue through ca.Issue, the same call the API serves, rather
//     than a template of their own. A credential minted from a private
//     template would be the one certificate the certificate policy does
//     not describe, on the day the policy is written.
//   - They write the store record. The service authorises a client by
//     looking its serial up in the store, not by trusting the chain, so
//     a certificate that is signed but unrecorded is one the service
//     refuses. Issuing without recording produces a valid-looking
//     credential that does not work, which is the most expensive kind of
//     failure to diagnose.
//   - They run while the service is stopped. The store is single-writer
//     SQLite on the service's own volume; two writers is not a
//     performance question but a locked database and a half-finished
//     bootstrap.

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/signingkey"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

// defaultCredentialValidity is how long both credentials are valid for
// unless -validity overrides it. Ninety days keeps a lost operator
// certificate or a compromised TLS key from mattering for a year, and is
// long enough that re-running these commands is not routine work.
//
// Nothing renews either certificate. Both commands are operator-run with
// the service stopped, so renewal is a diary entry, not a timer, and both
// print the expiry for that reason.
const defaultCredentialValidity = 90 * 24 * time.Hour

// issuerFlags are what both commands need to reach the intermediate and
// the records the service reads. They describe one token: the
// intermediate's. Neither command can name the root's, and neither has
// any reason to.
type issuerFlags struct {
	adapterName     *string
	modulePath      *string
	workspaceLabel  *string
	workspaceSerial *string
	pinEnv          *string
	keyLabel        *string
	certPath        *string
	curveName       *string
	baseURL         *string
	storePath       *string
	validity        *time.Duration
}

// addIssuerFlags registers the shared flags on fs.
func addIssuerFlags(fs *flag.FlagSet) *issuerFlags {
	return &issuerFlags{
		adapterName:     fs.String("adapter", config.AdapterSoftHSM2, "vendor adapter: \"softhsm2\" or \"protectserver\""),
		modulePath:      fs.String("module", "", "path to the PKCS#11 module (.so)"),
		workspaceLabel:  fs.String("workspace", "", "token label the intermediate key lives on"),
		workspaceSerial: fs.String("workspace-serial", "", "token serial number, to disambiguate when several tokens share the label"),
		pinEnv:          fs.String("pin-env", "", "environment variable holding the token's PIN"),
		keyLabel:        fs.String("intermediate-key-label", "", "CKA_LABEL of the intermediate's key pair; this command never creates one"),
		certPath:        fs.String("intermediate-cert", "", "path to the ceremony-produced intermediate certificate PEM"),
		curveName:       fs.String("intermediate-curve", "P-256", "EC curve the intermediate key was generated on: P-256, P-384, or P-521"),
		baseURL:         fs.String("base-url", "", "the service's ca.base_url; the issued certificate's CRL and AIA pointers are composed from it"),
		storePath:       fs.String("store", "", "the service's ca.store_path; the issued certificate is recorded there or the service will refuse it"),
		validity:        fs.Duration("validity", defaultCredentialValidity, "how long the issued certificate is valid for; nothing renews it"),
	}
}

// check validates everything reachable without the token, including the
// extra flags a particular command requires, and resolves the curve.
func (f *issuerFlags) check(extra map[string]string) (pk11.ECCurve, error) {
	required := map[string]string{
		"-module":                 *f.modulePath,
		"-workspace":              *f.workspaceLabel,
		"-pin-env":                *f.pinEnv,
		"-intermediate-key-label": *f.keyLabel,
		"-intermediate-cert":      *f.certPath,
		"-base-url":               *f.baseURL,
		"-store":                  *f.storePath,
	}
	for name, v := range extra {
		required[name] = v
	}
	for name, v := range required {
		if v == "" {
			return 0, fmt.Errorf("%s is required", name)
		}
	}
	if *f.validity <= 0 {
		return 0, fmt.Errorf("-validity must be positive, got %s", *f.validity)
	}
	// The same check internal/api applies to ca.base_url, run before the
	// token so a typo costs nothing. Both URLs are extensions, fixed at
	// signature time and never editable afterwards.
	if err := api.LeafDistributionFor(*f.baseURL).Validate(); err != nil {
		return 0, fmt.Errorf("-base-url: %w", err)
	}
	return config.ParseCurve(*f.curveName)
}

// openIssuer opens the store and loads the intermediate CA from the token.
// The store comes first: a mistyped path should fail before an operator
// is asked for a PIN, and before anything is signed.
//
// The caller owns both returned handles and closes them.
func openIssuer(ctx context.Context, f *issuerFlags, curve pk11.ECCurve) (*ca.CA, *store.SQLite, pk11.VendorAdapter, pk11.Workspace, error) {
	records, err := store.OpenSQLite(ctx, *f.storePath, nil, nil)
	if err != nil {
		return nil, nil, nil, pk11.Workspace{}, err
	}

	adapter, err := newVendorAdapter(*f.adapterName, *f.modulePath)
	if err != nil {
		_ = records.Close()
		return nil, nil, nil, pk11.Workspace{}, err
	}

	fail := func(err error) (*ca.CA, *store.SQLite, pk11.VendorAdapter, pk11.Workspace, error) {
		adapter.Close()
		_ = records.Close()
		return nil, nil, nil, pk11.Workspace{}, err
	}

	ws, err := findWorkspace(ctx, adapter, *f.workspaceLabel, *f.workspaceSerial)
	if err != nil {
		return fail(err)
	}
	// LoadIntermediate logs the token in and checks the certificate
	// against the key under the label: a CA certificate, not self-signed,
	// pathlen:0, inside its window, public key matching the token's.
	issuer, err := ca.LoadIntermediate(ctx, adapter, ws, pk11.DefaultSessionOptions(), pinResolver(*f.pinEnv), ca.LoadIntermediateParams{
		KeyLabel:     *f.keyLabel,
		CertPath:     *f.certPath,
		Curve:        curve,
		CertTTL:      *f.validity,
		Distribution: api.LeafDistributionFor(*f.baseURL),
	})
	if err != nil {
		return fail(err)
	}
	return issuer, records, adapter, ws, nil
}

// runIssueClientCertCmd issues the client certificate an operator
// authenticates to the write endpoints with, from a CSR the operator
// generated. The private key is theirs and never reaches this process.
//
// After the first one exists, further client certificates can be issued
// over the API by a client already in api.issuers. This command is for
// the first, and for the day the last one is lost.
func runIssueClientCertCmd(args []string) error {
	fs := flag.NewFlagSet("issue-client-cert", flag.ExitOnError)
	f := addIssuerFlags(fs)
	csrPath := fs.String("csr", "", "PEM certificate signing request from the client; the client's private key stays with the client")
	certOut := fs.String("cert-out", "", "path to write the issued client certificate PEM")

	if err := fs.Parse(args); err != nil {
		return err
	}
	curve, err := f.check(map[string]string{"-csr": *csrPath, "-cert-out": *certOut})
	if err != nil {
		return err
	}
	if err := refuseExistingFile(*certOut); err != nil {
		return err
	}

	csr, err := readCSRPEM(*csrPath)
	if err != nil {
		return err
	}
	// A certificate with neither a URI SAN nor a common name carries no
	// name api.issuers or api.revokers could list, so it would authorise
	// nothing however valid it is. Refused before it is signed rather
	// than issued and found inert.
	if len(csr.URIs) == 0 && csr.Subject.CommonName == "" {
		return fmt.Errorf("the CSR in %s carries neither a URI SAN nor a subject common name, "+
			"so no entry in api.issuers or api.revokers could ever match the certificate it would produce", *csrPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	issuer, records, adapter, _, err := openIssuer(ctx, f, curve)
	if err != nil {
		return err
	}
	defer adapter.Close()
	defer records.Close()

	cert, err := issuer.Issue(csr)
	if err != nil {
		return fmt.Errorf("issuing the client certificate: %w", err)
	}

	if err := recordAndWrite(ctx, records, *f.storePath, cert, *certOut); err != nil {
		return err
	}

	fmt.Printf("client certificate issued:\n  subject:   %s\n  serial:    %s\n  not after: %s\n  written:   %s\n  recorded:  %s\n",
		cert.Subject.String(), cert.SerialNumber, cert.NotAfter.UTC().Format(time.RFC3339), *certOut, *f.storePath)
	fmt.Printf("authorise it by putting one of these identities in api.issuers or api.revokers:\n")
	for _, id := range api.ClientIdentities(cert) {
		fmt.Printf("  %s\n", id)
	}
	fmt.Println("the lists are exact-match, and a name in neither authorises nothing")
	fmt.Println("nothing renews this certificate; re-run this command before it expires")
	return nil
}

// runProvisionTLSIdentityCmd generates the service's TLS key pair on the
// intermediate's token and issues the certificate the authenticated
// listener presents over it.
//
// The key is generated here and never leaves the token, so the service's
// TLS handshakes are signed by the HSM like everything else it signs. It
// is a separate key from the intermediate's, under its own versioned
// label, and the command refuses to use the intermediate's: a TLS
// handshake signs bytes the connecting peer chooses, and the key that
// signs certificates must never do that.
func runProvisionTLSIdentityCmd(args []string) error {
	fs := flag.NewFlagSet("provision-tls-identity", flag.ExitOnError)
	f := addIssuerFlags(fs)
	tlsKeyLabel := fs.String("tls-key-label", "", "versioned CKA_LABEL for the service's TLS key pair (e.g. ca-tls-key-v1); never the intermediate's")
	tlsCurveName := fs.String("curve", "P-256", "EC curve for the new TLS key pair: P-256, P-384, or P-521")
	dnsNames := fs.String("dns", "", "comma-separated DNS names the authenticated listener is reached at")
	ipAddresses := fs.String("ip", "", "comma-separated IP addresses the authenticated listener is reached at")
	commonName := fs.String("cn", "", "subject common name; defaults to the first -dns name")
	certOut := fs.String("cert-out", "", "path to write the service's TLS certificate PEM (server.tls.cert_path)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	curve, err := f.check(map[string]string{"-tls-key-label": *tlsKeyLabel, "-cert-out": *certOut})
	if err != nil {
		return err
	}
	tlsCurve, err := config.ParseCurve(*tlsCurveName)
	if err != nil {
		return fmt.Errorf("-curve: %w", err)
	}
	// Versioned, because a key that cannot be rotated without every
	// consumer changing on the same day is a key nobody rotates.
	if err := signingkey.ValidateLabel(*tlsKeyLabel); err != nil {
		return err
	}
	if *tlsKeyLabel == *f.keyLabel {
		return fmt.Errorf("-tls-key-label is the intermediate's own label %q: a TLS handshake signs bytes the peer chooses, "+
			"and the key that signs certificates must not. Give the TLS key its own versioned label", *tlsKeyLabel)
	}
	if err := refuseExistingFile(*certOut); err != nil {
		return err
	}

	names, ips, err := parseSANs(*dnsNames, *ipAddresses)
	if err != nil {
		return err
	}
	// A server certificate identified only by its subject is one no
	// modern client accepts: RFC 2818 and the CA/Browser Forum Baseline
	// Requirements retired the common name as an identity for server
	// authentication.
	if len(names) == 0 && len(ips) == 0 {
		return fmt.Errorf("-dns or -ip is required: a TLS server certificate with no subject alternative name is one no client will accept")
	}
	cn := *commonName
	if cn == "" && len(names) > 0 {
		cn = names[0]
	}
	if cn == "" {
		return fmt.Errorf("-cn is required when only -ip is given: the CSR needs a subject")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	issuer, records, adapter, ws, err := openIssuer(ctx, f, curve)
	if err != nil {
		return err
	}
	defer adapter.Close()
	defer records.Close()

	// Generation is irreversible: after this the label is taken, whatever
	// happens next. Everything checkable was checked above.
	key, err := provisionTLSKey(ctx, adapter, ws, signingkey.Params{Label: *tlsKeyLabel, Curve: tlsCurve})
	if err != nil {
		return err
	}

	// The CSR is signed by the key that was just generated, through the
	// HSM. That is not ceremony: it is the proof of possession every
	// other requester has to provide, and it means this certificate is
	// issued by exactly the path the API serves rather than by a second
	// template that could drift from it.
	csr, err := csrOverTokenKey(ctx, adapter, ws, *tlsKeyLabel, tlsCurve, pkix.Name{CommonName: cn}, names, ips)
	if err != nil {
		return fmt.Errorf("the TLS key pair %q was generated and its label is now taken, but building a CSR over it failed: %w", key.Label, err)
	}

	cert, err := issuer.Issue(csr)
	if err != nil {
		return fmt.Errorf("the TLS key pair %q was generated and its label is now taken, but issuing a certificate over it failed: %w", key.Label, err)
	}

	if err := recordAndWrite(ctx, records, *f.storePath, cert, *certOut); err != nil {
		return err
	}

	fmt.Printf("TLS identity provisioned:\n  token:     %s (serial %s)\n  key label: %s (%s)\n  subject:   %s\n  serial:    %s\n  not after: %s\n  written:   %s\n  recorded:  %s\n",
		ws.Label, ws.Serial, key.Label, *tlsCurveName, cert.Subject.String(), cert.SerialNumber,
		cert.NotAfter.UTC().Format(time.RFC3339), *certOut, *f.storePath)
	// Read back off the token rather than assumed from the template.
	fmt.Printf("token reports CKA_SENSITIVE=%t CKA_EXTRACTABLE=%t; the private key stays on the token\n", key.Sensitive, key.Extractable)
	fmt.Printf("point the service at it:\n  server.tls.key_label: %s\n  server.tls.cert_path: %s\n", key.Label, *certOut)
	fmt.Println("nothing renews this certificate; re-run this command under the next version label before it expires")
	return nil
}

// provisionTLSKey generates the TLS key pair on the token the
// intermediate already authenticated. Unlike provision-signing-key it
// does not refuse a token holding a CA hierarchy key: this key belongs on
// that token, beside the intermediate whose certificate chain it serves.
func provisionTLSKey(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, params signingkey.Params) (key signingkey.Key, err error) {
	s, err := adapter.OpenSession(ctx, ws, pk11.DefaultSessionOptions())
	if err != nil {
		return signingkey.Key{}, fmt.Errorf("opening a session on %q: %w", ws.Label, err)
	}
	defer func() {
		closeErr := adapter.CloseSession(ctx, s)
		if closeErr != nil && err == nil {
			err = fmt.Errorf("the key pair %q was generated but closing the session failed (the key is valid and must not be discarded): %w",
				params.Label, closeErr)
		}
	}()
	return signingkey.Provision(ctx, adapter, s, params)
}

// csrOverTokenKey builds and signs a certificate request with the key
// under label, which lives on the token and never leaves it.
func csrOverTokenKey(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, label string, curve pk11.ECCurve, subject pkix.Name, dnsNames []string, ips []net.IP) (*x509.CertificateRequest, error) {
	signer, err := ca.NewSigner(ctx, adapter, ws, pk11.DefaultSessionOptions(), label, curve)
	if err != nil {
		return nil, fmt.Errorf("loading the key %q to sign its own request: %w", label, err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     subject,
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}, signer)
	if err != nil {
		return nil, fmt.Errorf("creating the request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parsing the request just created: %w", err)
	}
	return csr, nil
}

// recordAndWrite records an issued certificate and writes it out.
//
// The certificate is written whatever the record did. It is signed, it
// cannot be unsigned, and a signed certificate the operator does not hold
// is one nobody can account for. A failed record is still an error,
// because the service authorises from the store: the certificate would be
// refused at every request and could never be revoked.
func recordAndWrite(ctx context.Context, records store.Store, storePath string, cert *x509.Certificate, certOut string) error {
	recErr := records.Record(ctx, store.CertRecord{
		Serial:   cert.SerialNumber,
		Subject:  cert.Subject,
		NotAfter: cert.NotAfter,
		Status:   store.StatusValid,
	})
	if err := writeCertPEM(certOut, cert.Raw); err != nil {
		if recErr != nil {
			return fmt.Errorf("certificate %s was issued, then recording it failed (%v) and writing it to %s failed too; "+
				"it exists nowhere and its serial is spent: %w", cert.SerialNumber, recErr, certOut, err)
		}
		return err
	}
	if recErr != nil {
		return fmt.Errorf("certificate %s was issued and written to %s, but recording it in %s failed, "+
			"so the service will refuse it and it can never be revoked; remove it and retry: %w",
			cert.SerialNumber, certOut, storePath, recErr)
	}
	return nil
}

// parseSANs splits the two comma-separated subject-alternative-name
// flags. An IP address that does not parse is refused rather than dropped
// or turned into a DNS name.
func parseSANs(dnsNames, ipAddresses string) ([]string, []net.IP, error) {
	var names []string
	for _, n := range strings.Split(dnsNames, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	var ips []net.IP
	for _, raw := range strings.Split(ipAddresses, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, nil, fmt.Errorf("-ip: %q is not an IP address", raw)
		}
		ips = append(ips, ip)
	}
	return names, ips, nil
}

// refuseExistingFile refuses to overwrite an output path. The file at a
// credential's path is a credential in use.
func refuseExistingFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing file %s", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking output path %s: %w", path, err)
	}
	return nil
}

// readCSRPEM reads exactly one PEM certificate request from path. More
// than one block is refused: picking the first would let file order
// decide which identity is certified.
func readCSRPEM(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s does not contain a PEM block", path)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("%s contains more than one PEM block; it must hold exactly one certificate request", path)
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%s holds a %q PEM block, want CERTIFICATE REQUEST", path, block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return csr, nil
}
