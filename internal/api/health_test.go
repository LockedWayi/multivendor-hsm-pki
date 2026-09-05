package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

func TestHealthz_AlwaysSucceeds(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
}

func TestHealthz_SucceedsEvenAfterAdapterClosed(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
		defer srv.Close()

		// Released rather than closed directly: Release both closes the
		// adapter and tells the harness it is gone, so cleanup reopens a
		// fresh connection instead of failing against a dead one. Closing it
		// behind the harness's back left this run's keys on the token every
		// time, reported only into a log line nobody read.
		b.Release()

		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d — /healthz must not depend on the HSM", resp.StatusCode, http.StatusOK)
		}
	})
}

func TestHealthReadyz_SucceedsWhenAdapterIsUp(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
}

// TestHealthReadyz_FailsWhenAdapterClosed is sub-task 2.6's own Done-when
// criterion, alongside TestHealthz_SucceedsEvenAfterAdapterClosed above:
// /readyz fails when the adapter is closed while /healthz still succeeds.
func TestHealthReadyz_FailsWhenAdapterClosed(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		srv := httptest.NewServer(api.NewServer(c, adapter, ws, records, 24*time.Hour, rootArtifacts, testLogger()))
		defer srv.Close()

		// Released rather than closed directly: Release both closes the
		// adapter and tells the harness it is gone, so cleanup reopens a
		// fresh connection instead of failing against a dead one. Closing it
		// behind the harness's back left this run's keys on the token every
		// time, reported only into a log line nobody read.
		b.Release()

		resp, err := http.Get(srv.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d after closing the adapter", resp.StatusCode, http.StatusServiceUnavailable)
		}
	})
}
