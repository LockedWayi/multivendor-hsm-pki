package pkcs11

import (
	"testing"
	"time"
)

func newTestSessionState(idle, maxTTL time.Duration) *Session {
	now := time.Now()
	return &Session{
		workspace:   Workspace{SlotID: 1, Label: "test"},
		openedAt:    now,
		lastUsedAt:  now,
		idleTimeout: idle,
		maxTTL:      maxTTL,
	}
}

func TestSession_TouchWithinBudget(t *testing.T) {
	s := newTestSessionState(time.Hour, time.Hour)
	if err := s.touch(); err != nil {
		t.Fatalf("touch() = %v, want nil", err)
	}
	if s.closed {
		t.Fatal("touch() closed a session within its budget")
	}
}

func TestSession_TouchIdleExpiry(t *testing.T) {
	s := newTestSessionState(10*time.Millisecond, time.Hour)
	time.Sleep(20 * time.Millisecond)
	if err := s.touch(); err != ErrSessionExpired {
		t.Fatalf("touch() = %v, want ErrSessionExpired", err)
	}
	if !s.closed {
		t.Fatal("touch() did not mark the session closed on idle expiry")
	}
	// Fail closed: a second touch after expiry stays rejected.
	if err := s.touch(); err != ErrSessionClosed {
		t.Fatalf("touch() after expiry = %v, want ErrSessionClosed", err)
	}
}

func TestSession_TouchMaxTTLExpiry(t *testing.T) {
	s := newTestSessionState(time.Hour, 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if err := s.touch(); err != ErrSessionExpired {
		t.Fatalf("touch() = %v, want ErrSessionExpired", err)
	}
}

func TestSession_TouchExtendsIdleWindow(t *testing.T) {
	s := newTestSessionState(30*time.Millisecond, time.Hour)
	// Two touches inside the idle window keep the session alive past what
	// a single 30ms budget would allow if it weren't being extended.
	time.Sleep(15 * time.Millisecond)
	if err := s.touch(); err != nil {
		t.Fatalf("first touch() = %v, want nil", err)
	}
	time.Sleep(15 * time.Millisecond)
	if err := s.touch(); err != nil {
		t.Fatalf("second touch() = %v, want nil (idle window should have been extended)", err)
	}
}

func TestSession_ExpiredDoesNotMutateState(t *testing.T) {
	s := newTestSessionState(10*time.Millisecond, time.Hour)
	time.Sleep(20 * time.Millisecond)
	if !s.expired() {
		t.Fatal("expired() = false, want true")
	}
	if s.closed {
		t.Fatal("expired() must not mark the session closed itself — only touch() and markClosed() do")
	}
}

func TestSession_MarkClosed(t *testing.T) {
	s := newTestSessionState(time.Hour, time.Hour)
	s.setLoggedIn(true)
	s.markClosed()
	if !s.closed || s.loggedIn {
		t.Fatalf("markClosed() left closed=%v loggedIn=%v, want true/false", s.closed, s.loggedIn)
	}
	if err := s.touch(); err != ErrSessionClosed {
		t.Fatalf("touch() on closed session = %v, want ErrSessionClosed", err)
	}
}

func TestSession_WorkspaceAndLoggedInAccessors(t *testing.T) {
	s := newTestSessionState(time.Hour, time.Hour)
	if got := s.Workspace(); got.SlotID != 1 || got.Label != "test" {
		t.Fatalf("Workspace() = %+v, want SlotID=1 Label=test", got)
	}
	if s.LoggedIn() {
		t.Fatal("LoggedIn() = true before any Login")
	}
	s.setLoggedIn(true)
	if !s.LoggedIn() {
		t.Fatal("LoggedIn() = false after setLoggedIn(true)")
	}
}
