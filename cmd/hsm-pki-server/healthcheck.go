package main

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// healthcheckTimeout bounds the self-probe. /healthz touches nothing but
// the process, so anything slower is already a symptom.
const healthcheckTimeout = 2 * time.Second

// probeAddress turns a listen address into one that can be dialled from
// inside the container. 0.0.0.0 and :: are wildcards for a listener, not
// destinations, so they become loopback. A specific bind address is kept.
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

// runHealthcheck probes this process's own /healthz. The runtime image has
// no shell and no HTTP client, so the binary probes itself. /healthz and
// not /readyz: readiness touches the HSM, and a transient HSM failure must
// not restart the container.
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
