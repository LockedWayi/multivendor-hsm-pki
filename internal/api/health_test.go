package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/api"
)

func TestHealthz_AlwaysSucceeds(t *testing.T) {
	c, adapter, ws := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, testLogger()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestHealthz_SucceedsEvenAfterAdapterClosed(t *testing.T) {
	c, adapter, ws := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, testLogger()))
	defer srv.Close()

	adapter.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d — /healthz must not depend on the HSM", resp.StatusCode, http.StatusOK)
	}
}

func TestHealthReadyz_SucceedsWhenAdapterIsUp(t *testing.T) {
	c, adapter, ws := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, testLogger()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestHealthReadyz_FailsWhenAdapterClosed is sub-task 2.6's own Done-when
// criterion, alongside TestHealthz_SucceedsEvenAfterAdapterClosed above:
// /readyz fails when the adapter is closed while /healthz still succeeds.
func TestHealthReadyz_FailsWhenAdapterClosed(t *testing.T) {
	c, adapter, ws := newTestCA(t)
	registry := api.NewRegistry()
	srv := httptest.NewServer(api.NewServer(c, adapter, ws, registry, 24*time.Hour, testLogger()))
	defer srv.Close()

	adapter.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d after closing the adapter", resp.StatusCode, http.StatusServiceUnavailable)
	}
}
