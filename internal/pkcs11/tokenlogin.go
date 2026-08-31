package pkcs11

import (
	"context"
	"fmt"

	p11 "github.com/miekg/pkcs11"
)

// Token login ("anchor login").
//
// # Why this exists
//
// PKCS#11 authenticates the *token for the whole application*, not the one
// session handle passed to C_Login. Once any session logs in as CKU_USER,
// every other session the application holds on that token is authenticated
// too; a second C_Login returns CKR_USER_ALREADY_LOGGED_IN, and C_Logout
// de-authenticates every session at once, including ones another caller is
// midway through using. Verified identical on SoftHSM2 2.6.1 and
// ProtectToolkit 7.3.3 — the symmetry across two unrelated implementations
// is what establishes it as the spec's model rather than a vendor quirk
// (docs/pkcs11-vendor-notes.md).
//
// The consequence is that a per-operation login/logout cycle cannot be made
// concurrency-safe by serializing the individual calls, because the
// interference happens *between* them. The service that does that breaks
// the moment two requests overlap, which is what this replaces.
//
// # The model
//
// A CA service is a daemon. It authenticates its token once at startup and
// stays authenticated until it shuts down, which is what the underlying
// PKCS#11 semantics were describing all along. LoginToken opens one
// internal anchor session and logs in on it; every later operation opens
// an ordinary session and simply uses it, with no login of its own,
// because the token is already authenticated. Close logs out.
//
// # What the anchor session is, and is not
//
// It is a raw PKCS#11 session handle held by the adapter, deliberately not
// a *Session and deliberately not registered with the janitor. Sessions in
// this package carry an idle timeout and a max TTL, and expiring is exactly
// what the anchor must never do — its expiry would silently drop the
// token's authentication out from under every in-flight caller. Keeping it
// outside that machinery is what makes "the session budget bounds a
// caller's session, never the daemon's authentication" true by
// construction rather than by a carefully chosen timeout.
//
// # The trade being accepted
//
// The token stays authenticated for the process's lifetime rather than for
// the span of one signature. That is the deliberate choice: it is what a
// PKI daemon does, it is the only model the per-token semantics actually
// support without serializing all work, and the PIN's exposure is
// unchanged either way (it lives in a C-heap buffer for the duration of one
// C_Login call and is zeroed immediately after — see SecurePIN). What it
// does mean is that a process compromised while running has an
// authenticated token available to it; the mitigation for that is the
// service not being compromised, not a login window measured in
// milliseconds that an attacker inside the process can simply wait for.

// LoginToken authenticates the token backing ws for this adapter, and keeps
// it authenticated until LogoutToken or Close. pin is consumed: it is
// zeroed in place before this returns, on every path.
//
// Calling it twice is an error rather than a silent no-op: a second call
// means a caller believes it is establishing authentication that another
// caller already owns, and quietly agreeing would leave the two of them
// disagreeing about who gets to log out.
func (a *pkcs11Adapter) LoginToken(ctx context.Context, ws Workspace, pin []byte, role Role) error {
	defer zeroizeBytes(pin)

	if err := checkCtx(ctx); err != nil {
		return err
	}
	if len(pin) == 0 {
		return ErrEmptyPIN
	}

	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	if a.tokenLoggedIn {
		return ErrTokenAlreadyLoggedIn
	}

	secure := NewSecurePIN(pin)
	defer secure.Zeroize()

	return a.withStateLock(func() error {
		handle, err := a.ctx.OpenSession(ws.SlotID, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
		if err != nil {
			return fmt.Errorf("C_OpenSession (anchor) slot %d: %w", ws.SlotID, err)
		}
		err = secure.withGoString(func(pinStr string) error {
			return a.ctx.Login(handle, uint(role), pinStr)
		})
		if err != nil {
			// Do not leak the anchor session on a failed login — a wrong
			// PIN is the expected way this fails, and a service that
			// retries would otherwise leak one session slot per attempt.
			_ = a.ctx.CloseSession(handle)
			return fmt.Errorf("C_Login (anchor): %w", err)
		}
		a.anchorSession = handle
		a.anchorWorkspace = ws
		a.tokenLoggedIn = true
		return nil
	})
}

// LogoutToken drops the token's authentication and releases the anchor
// session. Idempotent: logging out when not logged in is not an error,
// since the desired end state is already the actual one.
//
// Every session on the token is de-authenticated by this, including any a
// caller still holds — that is C_Logout's defined behaviour, not this
// method's choice.
func (a *pkcs11Adapter) LogoutToken(ctx context.Context) error {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	return a.logoutTokenLocked()
}

// logoutTokenLocked requires a.loginMu. Close uses it too, which is why it
// is factored out.
func (a *pkcs11Adapter) logoutTokenLocked() error {
	if !a.tokenLoggedIn {
		return nil
	}
	err := a.withStateLock(func() error {
		if err := a.ctx.Logout(a.anchorSession); err != nil {
			return fmt.Errorf("C_Logout (anchor): %w", err)
		}
		return nil
	})
	// Release the anchor session and clear the flag whatever C_Logout
	// reported. Leaving tokenLoggedIn set after a failed logout would
	// permanently block LoginToken from re-establishing authentication,
	// turning a transient error into an unrecoverable one.
	_ = a.withStateLock(func() error {
		return a.ctx.CloseSession(a.anchorSession)
	})
	a.anchorSession = 0
	a.anchorWorkspace = Workspace{}
	a.tokenLoggedIn = false
	return err
}

// TokenLoggedIn reports whether this adapter currently holds the token
// authenticated.
func (a *pkcs11Adapter) TokenLoggedIn() bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	return a.tokenLoggedIn
}
