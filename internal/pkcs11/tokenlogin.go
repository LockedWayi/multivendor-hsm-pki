package pkcs11

import (
	"context"
	"fmt"

	p11 "github.com/miekg/pkcs11"
)

// Token login.
//
// PKCS#11 authenticates the token for the whole application, not one
// session. Once any session logs in as CKU_USER, every session the
// application holds on that token is authenticated. A second C_Login
// returns CKR_USER_ALREADY_LOGGED_IN. C_Logout de-authenticates every
// session at once. SoftHSM2 2.6.1 and ProtectToolkit-C 7.3.3 software
// emulation behave the same way.
//
// A login and logout around each operation therefore cannot be made safe
// under concurrency by serializing the calls. The interference happens
// between them. The service logs in once at startup on an anchor session
// and stays logged in until it shuts down. Every later operation opens an
// ordinary session and uses it without a login of its own.
//
// The anchor session is a raw handle held by the adapter. It is not a
// *Session and it is not registered with the janitor. A session that
// expires would drop the token's authentication under every caller.
//
// The token stays authenticated for the process lifetime. A process
// compromised while running has an authenticated token available to it.
// The PIN lives in a SecurePIN for the duration of one C_Login call and is
// zeroed after it. One more copy exists that this package does not
// control: miekg/pkcs11's Login copies the PIN with C.CString and frees
// that buffer without zeroing it. See SecurePIN.

// LoginToken authenticates the token backing ws and keeps it authenticated
// until LogoutToken or Close. pin is zeroed in place before this returns,
// on every path. A second call is an error: two callers would then
// disagree about who logs out.
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
			// A wrong PIN is the expected failure. Closing the session
			// keeps a retrying service from leaking one session per attempt.
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
// session. Logging out when not logged in is not an error. C_Logout
// de-authenticates every session on the token, including any a caller
// still holds.
func (a *pkcs11Adapter) LogoutToken(ctx context.Context) error {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	return a.logoutTokenLocked()
}

// logoutTokenLocked requires a.loginMu. Close uses it too.
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
	// The flag is cleared whatever C_Logout reported. Leaving it set after
	// a failed logout would block LoginToken for good.
	_ = a.withStateLock(func() error {
		return a.ctx.CloseSession(a.anchorSession)
	})
	a.anchorSession = 0
	a.anchorWorkspace = Workspace{}
	a.tokenLoggedIn = false
	return err
}

// TokenLoggedIn reports whether this adapter holds the token authenticated.
func (a *pkcs11Adapter) TokenLoggedIn() bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	return a.tokenLoggedIn
}
