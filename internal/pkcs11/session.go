package pkcs11

import (
	"sync"
	"time"

	p11 "github.com/miekg/pkcs11"
)

// Session wraps one PKCS#11 session handle and enforces the idle-timeout
// and max-TTL budget it was opened with (docs/phases/phase-1-pkcs11-core.md
// acceptance criteria). It carries no PKCS#11 call logic itself — that
// belongs to the owning VendorAdapter, which serializes the underlying
// stateful PKCS#11 calls. Session only tracks whether it is still allowed
// to be used.
type Session struct {
	mu          sync.Mutex
	workspace   Workspace
	handle      p11.SessionHandle
	openedAt    time.Time
	lastUsedAt  time.Time
	idleTimeout time.Duration
	maxTTL      time.Duration
	loggedIn    bool
	closed      bool
}

// touch fails closed (CLAUDE.md §3.4) the instant a session's budget is
// exceeded, and records this call as activity otherwise. Every adapter
// operation that uses a session must call this first.
func (s *Session) touch() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	now := time.Now()
	if now.Sub(s.openedAt) > s.maxTTL || now.Sub(s.lastUsedAt) > s.idleTimeout {
		s.closed = true
		s.loggedIn = false
		return ErrSessionExpired
	}
	s.lastUsedAt = now
	return nil
}

// expired reports whether the session's budget has been exceeded without
// mutating lastUsedAt — used by the adapter's background janitor to find
// sessions to force-close even when nothing is actively using them.
func (s *Session) expired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return true
	}
	now := time.Now()
	return now.Sub(s.openedAt) > s.maxTTL || now.Sub(s.lastUsedAt) > s.idleTimeout
}

func (s *Session) markClosed() {
	s.mu.Lock()
	s.closed = true
	s.loggedIn = false
	s.mu.Unlock()
}

func (s *Session) setLoggedIn(v bool) {
	s.mu.Lock()
	s.loggedIn = v
	s.mu.Unlock()
}

// Workspace returns the workspace this session was opened against.
func (s *Session) Workspace() Workspace {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.workspace
}

// LoggedIn reports whether Login has succeeded on this session and Logout
// or expiry has not since occurred.
func (s *Session) LoggedIn() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loggedIn
}
