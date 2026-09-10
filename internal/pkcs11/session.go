package pkcs11

import (
	"sync"
	"time"

	p11 "github.com/miekg/pkcs11"
)

// Session wraps one PKCS#11 session handle and enforces the idle timeout
// and max TTL it was opened with. It carries no PKCS#11 call logic. The
// owning adapter serializes the calls; Session only tracks whether it may
// still be used.
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

// touch fails closed once the session's budget is exceeded, and records
// this call as activity otherwise. Every adapter operation that uses a
// session calls it first.
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

// expired reports whether the budget is exceeded, without touching
// lastUsedAt. The janitor uses it.
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
