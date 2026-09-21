package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/signingkey"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

const testBaseURL = "http://pki.example.test"

// issuedCA is what a ceremony leaves behind for these two commands to
// issue from.
type issuedCA struct {
	dir              string
	rootCert         *x509.Certificate
	intermediatePath string
	interKeyLabel    string
	pinEnv           string
	storePath        string
}

// bootstrapCA runs the real ceremony command and returns its output. The
// commands under test issue under the intermediate it produces, which is
// the arrangement an operator has when they reach this point.
func bootstrapCA(t *testing.T, b *hsmtest.Backend) issuedCA {
	t.Helper()
	dir := t.TempDir()
	// ceremonyArgs sets both PIN variables and releases the harness's
	// adapter, because each command opens the module itself.
	if err := runCeremonyCmd(ceremonyArgs(t, b, dir)); err != nil {
		t.Fatalf("ceremony: %v", err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(dir, "root.pem"))
	if err != nil {
		t.Fatalf("reading the ceremony root: %v", err)
	}
	block, _ := pem.Decode(rootPEM)
	if block == nil {
		t.Fatal("the ceremony root is not PEM")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the ceremony root: %v", err)
	}
	return issuedCA{
		dir:              dir,
		rootCert:         root,
		intermediatePath: filepath.Join(dir, "intermediate.pem"),
		interKeyLabel:    b.Label("cli-inter-key-v1"),
		pinEnv:           "KEYTOOL_TEST_INTER_PIN",
		storePath:        filepath.Join(dir, "ca.sqlite"),
	}
}

// issuerArgs is the flag set both commands share.
func issuerArgs(b *hsmtest.Backend, env issuedCA) []string {
	return []string{
		"-adapter", b.AdapterName,
		"-module", b.ModulePath,
		"-workspace", b.Primary.Label,
		"-pin-env", env.pinEnv,
		"-intermediate-key-label", env.interKeyLabel,
		"-intermediate-cert", env.intermediatePath,
		"-base-url", testBaseURL,
		"-store", env.storePath,
	}
}

// writeCSR generates a key the way a client does, on its own machine, and
// writes the request it would send. The private key is returned to the
// test and never goes near the command.
func writeCSR(t *testing.T, dir, name string, uris []string, commonName string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var parsed []*url.URL
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parsing the test URI SAN %q: %v", raw, err)
		}
		parsed = append(parsed, u)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
		URIs:    parsed,
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	path := filepath.Join(dir, name+".csr")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return key, path
}

// readCert reads a certificate the command wrote.
func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	cert, err := readCertPEM(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return cert
}

// requireRecorded fails unless the store holds serial as a valid
// certificate. The service authorises a client by this record, so a
// certificate missing from it is one the service refuses.
func requireRecorded(t *testing.T, storePath string, cert *x509.Certificate) {
	t.Helper()
	ctx := context.Background()
	records, err := store.OpenSQLite(ctx, storePath, nil, nil)
	if err != nil {
		t.Fatalf("opening the store the command wrote: %v", err)
	}
	defer records.Close()

	rec, found, err := records.Get(ctx, cert.SerialNumber)
	if err != nil {
		t.Fatalf("Get(%s): %v", cert.SerialNumber, err)
	}
	if !found {
		t.Fatalf("certificate %s is not in the store, so the service would refuse it", cert.SerialNumber)
	}
	if rec.Status != store.StatusValid {
		t.Fatalf("store status = %q, want %q", rec.Status, store.StatusValid)
	}
	if rec.Subject.String() != cert.Subject.String() {
		t.Fatalf("store subject = %q, want %q", rec.Subject.String(), cert.Subject.String())
	}
}

// withToken opens a fresh adapter and logs into the intermediate's token,
// the way the service does at startup.
func withToken(t *testing.T, b *hsmtest.Backend, env issuedCA, fn func(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace)) {
	t.Helper()
	adapter, err := newVendorAdapter(b.AdapterName, b.ModulePath)
	if err != nil {
		t.Fatalf("opening the module: %v", err)
	}
	defer adapter.Close()

	ctx := context.Background()
	ws, err := findWorkspace(ctx, adapter, b.Primary.Label, "")
	if err != nil {
		t.Fatalf("finding the token: %v", err)
	}
	pin, err := pinResolver(env.pinEnv)()
	if err != nil {
		t.Fatalf("resolving the PIN: %v", err)
	}
	if err := adapter.LoginToken(ctx, ws, pin, pk11.RoleUser); err != nil {
		t.Fatalf("logging in: %v", err)
	}
	defer func() { _ = adapter.LogoutToken(ctx) }()

	fn(ctx, adapter, ws)
}

// TestCredentials_TheServiceAcceptsWhatTheKeytoolIssues is the property
// both commands exist for: the service loads the TLS identity one of them
// provisioned, and completes a mutual-TLS handshake with the client
// certificate the other one issued.
//
// It is checked through the service's own code — ca.LoadServiceCertificate
// and api.TLSConfig — and through a real TLS 1.3 handshake, rather than by
// reading the certificates back with the same library that wrote them.
// The server's CertificateVerify in that handshake is signed by the HSM.
func TestCredentials_TheServiceAcceptsWhatTheKeytoolIssues(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		env := bootstrapCA(t, b)
		tlsKeyLabel := b.Label("ca-tls-key-v1")
		tlsCertPath := filepath.Join(env.dir, "tls.pem")

		tlsArgs := append(issuerArgs(b, env),
			"-tls-key-label", tlsKeyLabel,
			"-dns", "pki.example.test",
			"-cert-out", tlsCertPath,
		)
		if err := runProvisionTLSIdentityCmd(tlsArgs); err != nil {
			skipIfTheTokenRepeatedAKey(t, b, err, tlsKeyLabel, tlsCertPath)
			t.Fatalf("provision-tls-identity: %v", err)
		}
		serviceCert := readCert(t, tlsCertPath)
		requireRecorded(t, env.storePath, serviceCert)

		clientKey, csrPath := writeCSR(t, env.dir, "alice", []string{"urn:hsm-pki:operator:alice"}, "alice")
		clientCertPath := filepath.Join(env.dir, "client.pem")
		clientArgs := append(issuerArgs(b, env),
			"-csr", csrPath,
			"-cert-out", clientCertPath,
		)
		if err := runIssueClientCertCmd(clientArgs); err != nil {
			t.Fatalf("issue-client-cert: %v", err)
		}
		clientCert := readCert(t, clientCertPath)
		requireRecorded(t, env.storePath, clientCert)

		// The identity the configuration would name is derived by the
		// service's own function, not by the test's idea of it.
		if got := api.ClientIdentities(clientCert); len(got) == 0 || got[0] != "urn:hsm-pki:operator:alice" {
			t.Fatalf("api.ClientIdentities = %v, want the URI SAN first", got)
		}
		if !clientCert.NotAfter.After(time.Now()) {
			t.Fatalf("the client certificate is already expired at %s", clientCert.NotAfter)
		}

		intermediate := readCert(t, env.intermediatePath)

		withToken(t, b, env, func(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace) {
			identity, err := ca.LoadServiceCertificate(ctx, adapter, ws, pk11.DefaultSessionOptions(), intermediate, ca.ServiceCertificateParams{
				KeyLabel: tlsKeyLabel,
				CertPath: tlsCertPath,
				Curve:    pk11.P256,
			})
			if err != nil {
				t.Fatalf("the service refused the TLS identity this command provisioned: %v", err)
			}

			serverCfg := api.TLSConfig(identity, env.rootCert)
			pool := x509.NewCertPool()
			pool.AddCert(env.rootCert)
			clientCfg := &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    pool,
				ServerName: "pki.example.test",
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{clientCert.Raw, intermediate.Raw},
					PrivateKey:  clientKey,
					Leaf:        clientCert,
				}},
			}
			if err := handshake(t, serverCfg, clientCfg); err != nil {
				t.Fatalf("the mutual-TLS handshake failed: %v", err)
			}

			// The same handshake without the client certificate, so the
			// assertion above is known to have teeth rather than assumed
			// to: a check that cannot fail proves nothing.
			anonymous := clientCfg.Clone()
			anonymous.Certificates = nil
			if err := handshake(t, api.TLSConfig(identity, env.rootCert), anonymous); err == nil {
				t.Fatal("a client presenting no certificate completed the handshake")
			}
		})
	})
}

// handshake completes one TLS handshake over an in-memory pipe and
// reports the server's view of it first. In TLS 1.3 a client finishes
// before the server has validated its certificate, so the client's own
// verdict is the weaker one and is only returned when the server is
// satisfied.
//
// Each side closes its end when it is done, so a peer still waiting on a
// handshake that will never complete fails at once rather than at the
// deadline.
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) error {
	t.Helper()
	serverConn, clientConn := net.Pipe()

	deadline := time.Now().Add(10 * time.Second)
	_ = serverConn.SetDeadline(deadline)
	_ = clientConn.SetDeadline(deadline)

	serverErr := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		s := tls.Server(serverConn, serverCfg)
		err := s.HandshakeContext(context.Background())
		if err == nil && len(s.ConnectionState().PeerCertificates) == 0 {
			err = errors.New("the handshake completed without a client certificate")
		}
		serverErr <- err
	}()

	c := tls.Client(clientConn, clientCfg)
	clientErr := c.HandshakeContext(context.Background())
	clientConn.Close()

	if err := <-serverErr; err != nil {
		return err
	}
	return clientErr
}

// TestRunIssueClientCertCmd_TakesTheRequestTheRunbookTellsAnOperatorToMake
// runs the exact openssl command docs/key-ceremony-and-recovery.md §8.2
// publishes, feeds its output to the command, and verifies the chain that
// comes back with openssl again.
//
// Both halves are the point. A CSR this repository also generated would
// prove the code agrees with itself; an operator uses openssl, and the
// runbook is only correct if openssl's output is accepted and openssl
// accepts what comes out.
func TestRunIssueClientCertCmd_TakesTheRequestTheRunbookTellsAnOperatorToMake(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("openssl is not on PATH: %v", err)
	}
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		env := bootstrapCA(t, b)
		csrPath := filepath.Join(env.dir, "alice.csr")

		// Copied from the runbook, flag for flag.
		out, err := exec.Command(openssl, "req", "-new", "-newkey", "ec",
			"-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
			"-keyout", filepath.Join(env.dir, "alice.key"), "-out", csrPath,
			"-subj", "/CN=alice",
			"-addext", "subjectAltName=URI:urn:hsm-pki:operator:alice",
		).CombinedOutput()
		if err != nil {
			t.Fatalf("the openssl command the runbook publishes failed: %v: %s", err, out)
		}

		certPath := filepath.Join(env.dir, "alice.pem")
		if err := runIssueClientCertCmd(append(issuerArgs(b, env), "-csr", csrPath, "-cert-out", certPath)); err != nil {
			t.Fatalf("the command refused a request openssl produced: %v", err)
		}

		cert := readCert(t, certPath)
		requireRecorded(t, env.storePath, cert)
		if got := api.ClientIdentities(cert); len(got) == 0 || got[0] != "urn:hsm-pki:operator:alice" {
			t.Fatalf("api.ClientIdentities = %v, want the URI SAN openssl encoded", got)
		}

		// And the chain verifies in the implementation a relying party
		// actually runs.
		rootPath := filepath.Join(env.dir, "root.pem")
		if out, err := exec.Command(openssl, "verify", "-CAfile", rootPath,
			"-untrusted", env.intermediatePath, certPath).CombinedOutput(); err != nil {
			t.Fatalf("openssl verify: %v: %s", err, out)
		}
	})
}

// skipIfTheTokenRepeatedAKey handles the one refusal a correct command can
// return on a backend whose RNG restarts on every C_Initialize: the key
// just generated is a key pair already on the token, and Provision
// destroys it rather than hand it back. Measured on ProtectToolkit-C
// software emulation, where the command's first key pair is the ceremony's
// intermediate key, so without the refusal the service's TLS key would
// have been the CA's key.
//
// The refusal is asserted to be complete, then the rest of the test is
// skipped for that backend with the reason in the log, because what the
// test exists to measure cannot be measured on a token that is not a key
// source. It does not skip on any other error.
func skipIfTheTokenRepeatedAKey(t *testing.T, b *hsmtest.Backend, err error, label, certOut string) {
	t.Helper()
	if !errors.Is(err, signingkey.ErrDuplicateKey) {
		return
	}
	if _, statErr := os.Stat(certOut); !os.IsNotExist(statErr) {
		t.Fatalf("a certificate was written for a refused duplicate key: %v", err)
	}
	assertLabelIsFree(t, b, label)
	t.Skipf("%s: the token repeated a key pair it had already generated and the command refused it, writing nothing and freeing the label; "+
		"this backend is not a key source, so the identity cannot be provisioned here: %v", b.Name, err)
}

// TestRunProvisionTLSIdentityCmd_RefusesASecondKeyUnderTheSameLabel: key
// generation is irreversible, and a label that already names a key pair
// is not free. The second run must not overwrite the first.
func TestRunProvisionTLSIdentityCmd_RefusesASecondKeyUnderTheSameLabel(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		env := bootstrapCA(t, b)
		label := b.Label("ca-tls-key-v1")
		args := func(out string) []string {
			return append(issuerArgs(b, env),
				"-tls-key-label", label,
				"-dns", "pki.example.test",
				"-cert-out", filepath.Join(env.dir, out),
			)
		}
		if err := runProvisionTLSIdentityCmd(args("tls.pem")); err != nil {
			skipIfTheTokenRepeatedAKey(t, b, err, label, filepath.Join(env.dir, "tls.pem"))
			t.Fatalf("first run: %v", err)
		}
		err := runProvisionTLSIdentityCmd(args("tls-again.pem"))
		if err == nil || !strings.Contains(err.Error(), "label already in use") {
			t.Fatalf("second run = %v, want a refusal naming the taken label", err)
		}
		if _, statErr := os.Stat(filepath.Join(env.dir, "tls-again.pem")); statErr == nil {
			t.Fatal("the refused run wrote a certificate")
		}
	})
}

// TestRunIssueClientCertCmd_EachRunIsItsOwnCredential: two clients are
// two certificates with two serials, both recorded. A second run must not
// hand out the first one's identity.
func TestRunIssueClientCertCmd_EachRunIsItsOwnCredential(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		env := bootstrapCA(t, b)

		_, aliceCSR := writeCSR(t, env.dir, "alice", []string{"urn:hsm-pki:operator:alice"}, "alice")
		_, bobCSR := writeCSR(t, env.dir, "bob", nil, "bob")

		alicePath := filepath.Join(env.dir, "alice.pem")
		bobPath := filepath.Join(env.dir, "bob.pem")
		if err := runIssueClientCertCmd(append(issuerArgs(b, env), "-csr", aliceCSR, "-cert-out", alicePath)); err != nil {
			t.Fatalf("issuing alice: %v", err)
		}
		if err := runIssueClientCertCmd(append(issuerArgs(b, env), "-csr", bobCSR, "-cert-out", bobPath)); err != nil {
			t.Fatalf("issuing bob: %v", err)
		}

		alice, bob := readCert(t, alicePath), readCert(t, bobPath)
		if alice.SerialNumber.Cmp(bob.SerialNumber) == 0 {
			t.Fatal("both certificates carry the same serial")
		}
		requireRecorded(t, env.storePath, alice)
		requireRecorded(t, env.storePath, bob)

		// Bob asked with no URI SAN, so his common name is his identity.
		if got := api.ClientIdentities(bob); len(got) != 1 || got[0] != "bob" {
			t.Fatalf("api.ClientIdentities(bob) = %v, want the common name alone", got)
		}
		// The client certificate is usable for client authentication, which
		// is what the write endpoints need of it.
		hasClientAuth := false
		for _, eku := range alice.ExtKeyUsage {
			if eku == x509.ExtKeyUsageClientAuth {
				hasClientAuth = true
			}
		}
		if !hasClientAuth {
			t.Fatalf("the client certificate carries %v, want clientAuth among them", alice.ExtKeyUsage)
		}
	})
}

// TestRunIssueClientCertCmd_RefusesToOverwriteACredentialInUse: the file
// at -cert-out is a credential somebody is authenticating with.
func TestRunIssueClientCertCmd_RefusesToOverwriteACredentialInUse(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		env := bootstrapCA(t, b)
		_, csrPath := writeCSR(t, env.dir, "alice", []string{"urn:hsm-pki:operator:alice"}, "alice")
		out := filepath.Join(env.dir, "client.pem")

		if err := runIssueClientCertCmd(append(issuerArgs(b, env), "-csr", csrPath, "-cert-out", out)); err != nil {
			t.Fatalf("first run: %v", err)
		}
		first := readCert(t, out)

		err := runIssueClientCertCmd(append(issuerArgs(b, env), "-csr", csrPath, "-cert-out", out))
		if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
			t.Fatalf("second run = %v, want a refusal", err)
		}
		if again := readCert(t, out); again.SerialNumber.Cmp(first.SerialNumber) != 0 {
			t.Fatal("the refused run replaced the certificate that was there")
		}
	})
}

// noTokenArgs is a complete-looking flag set that points at no module and
// no PIN, so any error mentioning either means the command reached for
// the token before refusing.
func noTokenArgs(t *testing.T, extra ...string) []string {
	t.Helper()
	dir := t.TempDir()
	intermediate := filepath.Join(dir, "intermediate.pem")
	if err := os.WriteFile(intermediate, []byte("not a certificate, and never read\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return append([]string{
		"-module", "/nonexistent/module.so",
		"-workspace", "some-token",
		"-pin-env", "KEYTOOL_TEST_PIN_THAT_IS_NOT_SET",
		"-intermediate-key-label", "ca-intermediate-key-v1",
		"-intermediate-cert", intermediate,
		"-base-url", testBaseURL,
		"-store", filepath.Join(dir, "ca.sqlite"),
	}, extra...)
}

// validCSR writes a CSR that would be accepted, for the cases that are
// refused for another reason.
func validCSR(t *testing.T) string {
	t.Helper()
	_, path := writeCSR(t, t.TempDir(), "alice", []string{"urn:hsm-pki:operator:alice"}, "alice")
	return path
}

// TestCredentials_RefuseBeforeTouchingTheToken pins the ordering both
// commands promise: everything checkable without the HSM is checked
// before an operator is asked for a PIN and before anything is signed.
// No token.
func TestCredentials_RefuseBeforeTouchingTheToken(t *testing.T) {
	csr := validCSR(t)
	existing := filepath.Join(t.TempDir(), "taken.pem")
	if err := os.WriteFile(existing, []byte("a credential in use\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	twoBlocks := filepath.Join(t.TempDir(), "two.csr")
	oneBlock, err := os.ReadFile(csr)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := os.WriteFile(twoBlocks, append(append([]byte{}, oneBlock...), oneBlock...), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	noName := filepath.Join(t.TempDir(), "anonymous.csr")
	anonKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	anonDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, anonKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if err := os.WriteFile(noName, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: anonDER}), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	client := func(extra ...string) []string { return noTokenArgs(t, extra...) }

	cases := []struct {
		name string
		run  func([]string) error
		args []string
		want string
	}{
		{
			"a client CSR that nothing could authorise",
			runIssueClientCertCmd,
			client("-csr", noName, "-cert-out", filepath.Join(t.TempDir(), "out.pem")),
			"neither a URI SAN nor a subject common name",
		},
		{
			"a client CSR file that is not there",
			runIssueClientCertCmd,
			client("-csr", "/nonexistent/client.csr", "-cert-out", filepath.Join(t.TempDir(), "out.pem")),
			"reading /nonexistent/client.csr",
		},
		{
			"a file holding two requests",
			runIssueClientCertCmd,
			client("-csr", twoBlocks, "-cert-out", filepath.Join(t.TempDir(), "out.pem")),
			"more than one PEM block",
		},
		{
			"a client certificate path already in use",
			runIssueClientCertCmd,
			client("-csr", csr, "-cert-out", existing),
			"refusing to overwrite",
		},
		{
			"no CSR given",
			runIssueClientCertCmd,
			client("-cert-out", filepath.Join(t.TempDir(), "out.pem")),
			"-csr is required",
		},
		{
			"a base URL a certificate cannot carry",
			runIssueClientCertCmd,
			append(client("-csr", csr, "-cert-out", filepath.Join(t.TempDir(), "out.pem")), "-base-url", "ldap://pki.example.test"),
			"-base-url",
		},
		{
			"a validity of zero",
			runIssueClientCertCmd,
			append(client("-csr", csr, "-cert-out", filepath.Join(t.TempDir(), "out.pem")), "-validity", "0s"),
			"-validity must be positive",
		},
		{
			"the intermediate's own label as the TLS key",
			runProvisionTLSIdentityCmd,
			client("-tls-key-label", "ca-intermediate-key-v1", "-dns", "pki.example.test", "-cert-out", filepath.Join(t.TempDir(), "out.pem")),
			"a TLS handshake signs bytes the peer chooses",
		},
		{
			"an unversioned TLS key label",
			runProvisionTLSIdentityCmd,
			client("-tls-key-label", "ca-tls-key", "-dns", "pki.example.test", "-cert-out", filepath.Join(t.TempDir(), "out.pem")),
			"versioned label",
		},
		{
			"a TLS certificate with no subject alternative name",
			runProvisionTLSIdentityCmd,
			client("-tls-key-label", "ca-tls-key-v1", "-cert-out", filepath.Join(t.TempDir(), "out.pem")),
			"no client will accept",
		},
		{
			"an IP that is not an IP",
			runProvisionTLSIdentityCmd,
			client("-tls-key-label", "ca-tls-key-v1", "-ip", "10.0.0.256", "-cert-out", filepath.Join(t.TempDir(), "out.pem")),
			"is not an IP address",
		},
		{
			"no store given",
			runProvisionTLSIdentityCmd,
			append(client("-tls-key-label", "ca-tls-key-v1", "-dns", "pki.example.test", "-cert-out", filepath.Join(t.TempDir(), "out.pem")), "-store", ""),
			"-store is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(tc.args)
			if err == nil {
				t.Fatal("the command succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to say %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "module") || strings.Contains(err.Error(), "PIN") {
				t.Fatalf("refused for the wrong reason, after reaching for the token: %v", err)
			}
		})
	}
}

// TestCredentials_RefusalsWriteNoStore: a command that refuses before the
// token must not have created the service's database on the way. No
// token.
func TestCredentials_RefusalsWriteNoStore(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "ca.sqlite")
	args := append(noTokenArgs(t, "-csr", validCSR(t), "-cert-out", filepath.Join(dir, "out.pem")), "-store", storePath, "-validity", "-1h")

	if err := runIssueClientCertCmd(args); err == nil {
		t.Fatal("the command succeeded")
	}
	if _, err := os.Stat(storePath); !os.IsNotExist(err) {
		t.Fatalf("a refused run created %s", storePath)
	}
}

// TestRun_RoutesTheCredentialSubcommands: a subcommand missing from run's
// switch cannot be invoked. No token.
func TestRun_RoutesTheCredentialSubcommands(t *testing.T) {
	for _, name := range []string{"issue-client-cert", "provision-tls-identity"} {
		t.Run(name, func(t *testing.T) {
			err := run([]string{name})
			if err == nil {
				t.Fatalf("run(%s) with no flags succeeded, want an error", name)
			}
			if strings.Contains(err.Error(), "unknown command") {
				t.Fatalf("%s is not routed by run: %v", name, err)
			}
		})
	}
}

// TestParseSANs covers the splitting on its own, including the shapes a
// flag picks up from a shell. No token.
func TestParseSANs(t *testing.T) {
	names, ips, err := parseSANs(" pki.example.test , localhost ,", "10.0.0.1, ::1")
	if err != nil {
		t.Fatalf("parseSANs: %v", err)
	}
	if len(names) != 2 || names[0] != "pki.example.test" || names[1] != "localhost" {
		t.Fatalf("names = %v, want the two trimmed names", names)
	}
	if len(ips) != 2 || !ips[0].Equal(net.ParseIP("10.0.0.1")) || !ips[1].Equal(net.ParseIP("::1")) {
		t.Fatalf("ips = %v, want the two addresses", ips)
	}
	if _, _, err := parseSANs("", "not-an-ip"); err == nil {
		t.Fatal("an unparseable IP was accepted")
	}
}
