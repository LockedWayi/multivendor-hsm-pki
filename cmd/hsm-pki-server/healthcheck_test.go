package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These tests touch no token: the health check is pure process-local HTTP,
// so running them once is running them everywhere (CLAUDE.md §2.4,
// docs/test-matrix.md §4).

func TestProbeAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		listen  string
		want    string
		wantErr bool
	}{
		{name: "IPv4 wildcard becomes loopback", listen: "0.0.0.0:8080", want: "127.0.0.1:8080"},
		{name: "IPv6 wildcard becomes loopback", listen: "[::]:8080", want: "127.0.0.1:8080"},
		{name: "bare port becomes loopback", listen: ":8080", want: "127.0.0.1:8080"},
		{name: "specific bind address is kept", listen: "10.1.2.3:9443", want: "10.1.2.3:9443"},
		{name: "loopback is kept", listen: "127.0.0.1:8080", want: "127.0.0.1:8080"},
		{name: "IPv6 literal is kept and re-bracketed", listen: "[fd00::1]:8080", want: "[fd00::1]:8080"},
		{name: "no port at all is an error", listen: "0.0.0.0", wantErr: true},
		{name: "empty is an error", listen: "", wantErr: true},
		{name: "port omitted after colon is an error", listen: "0.0.0.0:", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := probeAddress(tc.listen)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("probeAddress(%q) = %q, want an error", tc.listen, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("probeAddress(%q): %v", tc.listen, err)
			}
			if got != tc.want {
				t.Fatalf("probeAddress(%q) = %q, want %q", tc.listen, got, tc.want)
			}
		})
	}
}

// listenAddrOf returns a test server's address in the listen_addr form the
// config would carry, so the test drives runHealthcheck exactly as main does.
func listenAddrOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		t.Fatalf("test server URL %q is not host:port: %v", srv.URL, err)
	}
	return addr
}

func TestRunHealthcheck_HealthyWhenHealthzAnswers200(t *testing.T) {
	var probedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := runHealthcheck(listenAddrOf(t, srv)); err != nil {
		t.Fatalf("runHealthcheck: %v", err)
	}
	// The path matters: /readyz would make a transient HSM failure look
	// like a dead process and get the container restarted.
	if probedPath != "/healthz" {
		t.Fatalf("probed %q, want /healthz", probedPath)
	}
}

func TestRunHealthcheck_UnhealthyOnNon200(t *testing.T) {
	// 503 is what internal/api returns when it will not serve. A health
	// check that reported success on any answer at all would be worse than
	// no health check: it would assert liveness on the strength of the TCP
	// stack alone.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if err := runHealthcheck(listenAddrOf(t, srv)); err == nil {
		t.Fatal("runHealthcheck accepted a 503, want an error")
	}
}

func TestRunHealthcheck_UnhealthyWhenNothingIsListening(t *testing.T) {
	// Bind and immediately release a port, so the address is well-formed
	// and reliably nobody's — the container-started-but-service-dead case.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := runHealthcheck(addr); err == nil {
		t.Fatalf("runHealthcheck(%q) succeeded against a closed port, want an error", addr)
	}
}

func TestRunHealthcheck_RejectsUnusableListenAddr(t *testing.T) {
	if err := runHealthcheck("not-an-address"); err == nil {
		t.Fatal("runHealthcheck accepted a malformed listen address, want an error")
	}
}
