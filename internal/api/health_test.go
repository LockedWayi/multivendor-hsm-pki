package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

func TestHealthz_AlwaysSucceeds(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		resp, err := http.Get(ts.public.URL + "/healthz")
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
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		// Release, not Close: the harness then reopens a fresh connection for
		// cleanup instead of failing against a closed one.
		b.Release()

		resp, err := http.Get(ts.public.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d; /healthz must not depend on the HSM", resp.StatusCode, http.StatusOK)
		}
	})
}

func TestHealthReadyz_SucceedsWhenAdapterIsUp(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		resp, err := http.Get(ts.public.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
}

// TestHealthReadyz_FailsWhenAdapterClosed: /readyz fails when the adapter
// is closed while /healthz still succeeds.
func TestHealthReadyz_FailsWhenAdapterClosed(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		c, adapter, ws, rootArtifacts := newTestCA(t, b)
		records := store.NewMemory()
		ts := startServers(t, c, adapter, ws, records, 24*time.Hour, rootArtifacts)
		defer ts.Close()

		// Release, not Close: the harness then reopens a fresh connection for
		// cleanup instead of failing against a closed one.
		b.Release()

		resp, err := http.Get(ts.public.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d after closing the adapter", resp.StatusCode, http.StatusServiceUnavailable)
		}
	})
}
