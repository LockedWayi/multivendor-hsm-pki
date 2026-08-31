package main

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// healthcheckTimeout bounds the self-probe. It is deliberately short: a
// liveness probe that hangs is indistinguishable from a healthy one to the
// orchestrator waiting on it, and /healthz touches nothing but the process
// itself, so anything slower than this is already a symptom.
const healthcheckTimeout = 2 * time.Second

// probeAddress converts a listen address into one that can be dialled from
// inside the same container.
//
// A wildcard bind is not a destination: 0.0.0.0 means "every local
// interface" to a listener and is not a routable address to a dialler, and
// :: has the same problem. Both are rewritten to loopback, which is the
// only interface a probe running beside the process should ever use — a
// health check that leaves the container is testing the network, not the
// service. A specific bind address is kept as it is, because an operator
// who narrowed the listener meant it.
func probeAddress(listenAddr string) (string, error) {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("server.listen_addr %q: %w", listenAddr, err)
	}
	if port == "" {
		return "", fmt.Errorf("server.listen_addr %q names no port", listenAddr)
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// runHealthcheck probes this process's own /healthz and reports whether it
// answered. It exists because the runtime image has no shell and no HTTP
// client for a HEALTHCHECK to invoke, and adding either to get a health
// check would mean putting a general-purpose tool into a container whose
// value is that it has none (docs/phases/phase-4-container-k8s.md, 4.2).
// The binary is already in the image and already knows the listen address,
// so it probes itself.
//
// /healthz and not /readyz, deliberately. Liveness answers "is this process
// working"; readiness answers "should it receive traffic", which here means
// touching the HSM. A transient HSM blip must not read as a dead container
// and get it restarted — that turns a recoverable dependency failure into
// an outage, and restarts do not fix an HSM (internal/api/health.go).
func runHealthcheck(listenAddr string) error {
	addr, err := probeAddress(listenAddr)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: healthcheckTimeout}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return fmt.Errorf("probing %s: %w", addr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probing %s: /healthz returned %s", addr, resp.Status)
	}
	return nil
}
