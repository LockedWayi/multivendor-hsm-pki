package pkcs11

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	p11 "github.com/miekg/pkcs11"
)

// janitorInterval is how often the background sweep closes sessions past
// their idle timeout or max TTL. The sweep is not exercised on its own
// timing in the tests: a module allows one C_Initialize per process, so a
// second short-interval adapter cannot run beside the test adapter. touch
// checks the same budget on every call.
const janitorInterval = 30 * time.Second

// pkcs11Adapter is the PKCS#11 implementation shared by every
// VendorAdapter in this package. It is unexported: callers see
// SoftHSM2Adapter or ProtectServerAdapter, each a named type embedding it.
// Neither adds an override. SoftHSM2 and ProtectToolkit-C software
// emulation both pass the conformance suite with this code. That is two
// spec-conformant implementations. It is not proof that the abstraction is
// complete. nShield and Luna are untested, and that is where differences
// are expected: login and key protection model, CKA_ID and label
// handling, EC point encoding, session limits, error codes.
//
// Each pkcs11Adapter owns its own *p11.Ctx and its own lock. A process can
// hold one adapter per module.
//
// Lock order: withStateLock (exclusive) for every multi-step sequence on a
// session (FindObjectsInit/FindObjects/FindObjectsFinal, SignInit/Sign,
// Login, GenerateKeyPair) and for C_GetSlotList. withReadLock (shared)
// only for single-call operations: C_GetAttributeValue and
// C_GenerateRandom.
type pkcs11Adapter struct {
	mu     sync.RWMutex
	ctx    *p11.Ctx
	closed bool

	sessMu   sync.Mutex
	sessions map[p11.SessionHandle]*Session

	// Anchor login state. See tokenlogin.go.
	loginMu         sync.Mutex
	anchorSession   p11.SessionHandle
	anchorWorkspace Workspace
	tokenLoggedIn   bool

	janitorStop chan struct{}
	janitorDone chan struct{}
	closeOnce   sync.Once
}

// newPKCS11Adapter loads and initializes the module at modulePath and
// starts the session janitor. Every vendor constructor calls it.
func newPKCS11Adapter(modulePath string) (*pkcs11Adapter, error) {
	ctx := p11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: failed to load module %q", modulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: C_Initialize: %w", err)
	}

	a := &pkcs11Adapter{
		ctx:         ctx,
		sessions:    make(map[p11.SessionHandle]*Session),
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
	}
	go a.janitor(janitorInterval)
	return a, nil
}

func (a *pkcs11Adapter) withStateLock(fn func() error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrAdapterClosed
	}
	return fn()
}

// withReadLock runs fn under a shared lock. Only C_GetAttributeValue and
// C_GenerateRandom use it. Any operation with an *Init step needs
// withStateLock, or two sessions' operation state interleaves. A read
// lock is also a claim about a vendor's threading: ProtectToolkit-C 7.3.3
// deadlocks inside C_GetSlotList under concurrent callers despite
// CKF_OS_LOCKING_OK, so Workspaces takes the exclusive lock. Test a new
// read-lock caller on every backend first.
func (a *pkcs11Adapter) withReadLock(fn func() error) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return ErrAdapterClosed
	}
	return fn()
}

func checkCtx(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// ─── Workspaces ─────────────────────────────────────────────────────────

// Workspaces enumerates the tokens the module can see. It takes the
// exclusive lock. ProtectToolkit-C 7.3.3 software emulation deadlocked
// inside C_GetSlotList with two concurrent callers under a read lock,
// although the module is initialized with CKF_OS_LOCKING_OK. The cost is
// that a module stalled in C_GetSlotList stalls every other operation.
// TestConformance/*/Workspaces_ConcurrentCallsAreSafe hangs on that
// backend if this goes back to withReadLock.
func (a *pkcs11Adapter) Workspaces(ctx context.Context) ([]Workspace, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	var out []Workspace
	err := a.withStateLock(func() error {
		ids, err := a.ctx.GetSlotList(true)
		if err != nil {
			return fmt.Errorf("C_GetSlotList: %w", err)
		}
		for _, id := range ids {
			ti, err := a.ctx.GetTokenInfo(id)
			if err != nil {
				continue
			}
			out = append(out, Workspace{
				SlotID: id,
				Label:  strings.TrimRight(ti.Label, " "),
				// PKCS#11 pads both fixed-width fields with spaces.
				Serial:  strings.TrimRight(ti.SerialNumber, " "),
				Present: true,
			})
		}
		return nil
	})
	return out, err
}

// ─── Session lifecycle ─────────────────────────────────────────────────

func (a *pkcs11Adapter) OpenSession(ctx context.Context, ws Workspace, opts SessionOptions) (*Session, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if opts.IdleTimeout <= 0 || opts.MaxTTL <= 0 {
		d := DefaultSessionOptions()
		if opts.IdleTimeout <= 0 {
			opts.IdleTimeout = d.IdleTimeout
		}
		if opts.MaxTTL <= 0 {
			opts.MaxTTL = d.MaxTTL
		}
	}

	var handle p11.SessionHandle
	err := a.withStateLock(func() error {
		h, err := a.ctx.OpenSession(ws.SlotID, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
		if err != nil {
			return fmt.Errorf("C_OpenSession slot %d: %w", ws.SlotID, err)
		}
		handle = h
		return nil
	})
	if err != nil {
		return nil, err
	}

	now := time.Now()
	s := &Session{
		workspace:   ws,
		handle:      handle,
		openedAt:    now,
		lastUsedAt:  now,
		idleTimeout: opts.IdleTimeout,
		maxTTL:      opts.MaxTTL,
	}
	a.sessMu.Lock()
	a.sessions[handle] = s
	a.sessMu.Unlock()
	return s, nil
}

// CloseSession releases the underlying PKCS#11 session.
//
// The session is marked unusable at once, whatever the token reports. It
// is removed from the session map only once the token has released the
// handle: on success, on CKR_SESSION_HANDLE_INVALID (already gone, the
// result of a double close), or on ErrAdapterClosed (Close finalized the
// module). An entry dropped before that would leave a session open on the
// token that neither the janitor nor Close can reclaim, and session slots
// are finite.
func (a *pkcs11Adapter) CloseSession(ctx context.Context, s *Session) error {
	s.markClosed()

	err := a.withStateLock(func() error {
		if err := a.ctx.CloseSession(s.handle); err != nil {
			return fmt.Errorf("C_CloseSession: %w", err)
		}
		return nil
	})

	if err == nil || errors.Is(err, ErrAdapterClosed) || isSessionHandleInvalid(err) {
		a.sessMu.Lock()
		delete(a.sessions, s.handle)
		a.sessMu.Unlock()
	}
	return err
}

// isSessionHandleInvalid reports whether the token says the handle is gone.
func isSessionHandleInvalid(err error) bool {
	var p11Err p11.Error
	return errors.As(err, &p11Err) && p11Err == p11.Error(p11.CKR_SESSION_HANDLE_INVALID)
}

// ─── Login / Logout ─────────────────────────────────────────────────────

// Login authenticates the session as role.
//
// pin is zeroed in place before this returns, on every path. The wipe is
// deferred first, so a guard clause failing before NewSecurePIN does not
// hand the caller back a readable PIN. The PIN reaches the binding as a Go
// string aliasing the C buffer. The binding then makes its own C copy with
// C.CString and frees it without zeroing. See SecurePIN.
func (a *pkcs11Adapter) Login(ctx context.Context, s *Session, pin []byte, role Role) error {
	defer zeroizeBytes(pin)

	if err := checkCtx(ctx); err != nil {
		return err
	}
	if err := s.touch(); err != nil {
		return err
	}
	if len(pin) == 0 {
		return ErrEmptyPIN
	}

	secure := NewSecurePIN(pin)
	defer secure.Zeroize()

	err := a.withStateLock(func() error {
		return secure.withGoString(func(pinStr string) error {
			return a.ctx.Login(s.handle, uint(role), pinStr)
		})
	})
	if err != nil {
		return fmt.Errorf("C_Login: %w", err)
	}
	s.setLoggedIn(true)
	return nil
}

func (a *pkcs11Adapter) Logout(ctx context.Context, s *Session) error {
	if err := checkCtx(ctx); err != nil {
		return err
	}
	if err := s.touch(); err != nil {
		return err
	}
	err := a.withStateLock(func() error {
		if err := a.ctx.Logout(s.handle); err != nil {
			return fmt.Errorf("C_Logout: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.setLoggedIn(false)
	return nil
}

// ─── Key generation ─────────────────────────────────────────────────────

func (a *pkcs11Adapter) GenerateKeyPair(ctx context.Context, s *Session, req KeyPairRequest) (KeyPairHandle, error) {
	if err := checkCtx(ctx); err != nil {
		return KeyPairHandle{}, err
	}
	if err := s.touch(); err != nil {
		return KeyPairHandle{}, err
	}
	ecParams, err := ecCurveOID(req.Curve)
	if err != nil {
		return KeyPairHandle{}, err
	}
	id, err := resolveID(req.ID)
	if err != nil {
		return KeyPairHandle{}, err
	}

	pubTemplate := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_LABEL, req.Label),
		p11.NewAttribute(p11.CKA_ID, id),
		p11.NewAttribute(p11.CKA_EC_PARAMS, ecParams),
		p11.NewAttribute(p11.CKA_VERIFY, req.Verify),
	}
	privTemplate := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_PRIVATE, true),
		p11.NewAttribute(p11.CKA_LABEL, req.Label),
		p11.NewAttribute(p11.CKA_ID, id),
		p11.NewAttribute(p11.CKA_SIGN, req.Sign),
		// CKA_SENSITIVE is forced true. With it false, PKCS#11 lets a
		// token disclose the private key through C_GetAttributeValue.
		// SoftHSM2 refuses anyway. ProtectToolkit-C 7.3.3 returned all 32
		// bytes to any authenticated session. No key this platform creates
		// has a use for a readable private key.
		p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, req.Extractable),
	}

	var pub, priv p11.ObjectHandle
	err = a.withStateLock(func() error {
		mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_EC_KEY_PAIR_GEN, nil)}
		pu, pr, err := a.ctx.GenerateKeyPair(s.handle, mech, pubTemplate, privTemplate)
		if err != nil {
			return fmt.Errorf("C_GenerateKeyPair: %w", err)
		}
		pub, priv = pu, pr
		return nil
	})
	if err != nil {
		return KeyPairHandle{}, err
	}
	return KeyPairHandle{Public: ObjectHandle(pub), Private: ObjectHandle(priv)}, nil
}

func (a *pkcs11Adapter) GenerateSecretKey(ctx context.Context, s *Session, req SecretKeyRequest) (ObjectHandle, error) {
	if err := checkCtx(ctx); err != nil {
		return 0, err
	}
	if err := s.touch(); err != nil {
		return 0, err
	}
	bits := req.KeyBits
	if bits == 0 {
		bits = 256
	}
	// Checked here, not left to the token. CKA_VALUE_LEN is bits/8, and
	// integer division would turn 200 bits into a 25-byte length that some
	// tokens accept as a non-standard AES key.
	switch bits {
	case 128, 192, 256:
	default:
		return 0, fmt.Errorf("%w: %d bits (want 128, 192, or 256)", ErrUnsupportedKeySize, bits)
	}
	id, err := resolveID(req.ID)
	if err != nil {
		return 0, err
	}

	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_LABEL, req.Label),
		p11.NewAttribute(p11.CKA_ID, id),
		p11.NewAttribute(p11.CKA_VALUE_LEN, bits/8),
		p11.NewAttribute(p11.CKA_ENCRYPT, req.Encrypt),
		p11.NewAttribute(p11.CKA_DECRYPT, req.Decrypt),
		p11.NewAttribute(p11.CKA_WRAP, req.Wrap),
		p11.NewAttribute(p11.CKA_UNWRAP, req.Unwrap),
		p11.NewAttribute(p11.CKA_SENSITIVE, req.Sensitive),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, req.Extractable),
	}

	var handle p11.ObjectHandle
	err = a.withStateLock(func() error {
		mech := []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_GEN, nil)}
		h, err := a.ctx.GenerateKey(s.handle, mech, template)
		if err != nil {
			return fmt.Errorf("C_GenerateKey: %w", err)
		}
		handle = h
		return nil
	})
	if err != nil {
		return 0, err
	}
	return ObjectHandle(handle), nil
}

func (a *pkcs11Adapter) GenerateRandom(ctx context.Context, s *Session, n int) ([]byte, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if err := s.touch(); err != nil {
		return nil, err
	}
	var out []byte
	err := a.withReadLock(func() error {
		b, err := a.ctx.GenerateRandom(s.handle, n)
		if err != nil {
			return fmt.Errorf("C_GenerateRandom: %w", err)
		}
		out = b
		return nil
	})
	return out, err
}

// ─── Find / attributes ──────────────────────────────────────────────────

// DestroyObject removes obj from the token. See VendorAdapter for why it
// takes a handle and not a label.
func (a *pkcs11Adapter) DestroyObject(ctx context.Context, s *Session, obj ObjectHandle) error {
	if err := checkCtx(ctx); err != nil {
		return err
	}
	if err := s.touch(); err != nil {
		return err
	}
	return a.withStateLock(func() error {
		if err := a.ctx.DestroyObject(s.handle, p11.ObjectHandle(obj)); err != nil {
			return fmt.Errorf("C_DestroyObject: %w", err)
		}
		return nil
	})
}

// findObjectsBatch is how many handles one C_FindObjects call asks for.
// The loop continues until the token returns nothing, so the batch size
// never bounds a search.
const findObjectsBatch = 50

func (a *pkcs11Adapter) FindObjects(ctx context.Context, s *Session, tmpl []Attribute) ([]ObjectHandle, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if err := s.touch(); err != nil {
		return nil, err
	}
	p11Template := toP11Attributes(tmpl)

	var out []ObjectHandle
	err := a.withStateLock(func() error {
		if err := a.ctx.FindObjectsInit(s.handle, p11Template); err != nil {
			return fmt.Errorf("C_FindObjectsInit: %w", err)
		}
		defer a.ctx.FindObjectsFinal(s.handle)
		// Loop until a batch comes back empty. miekg/pkcs11 documents the
		// returned boolean as deprecated. An earlier version stopped on
		// that boolean, and every search silently returned one batch.
		for {
			batch, _, err := a.ctx.FindObjects(s.handle, findObjectsBatch)
			if err != nil {
				return fmt.Errorf("C_FindObjects: %w", err)
			}
			if len(batch) == 0 {
				break
			}
			for _, h := range batch {
				out = append(out, ObjectHandle(h))
			}
		}
		return nil
	})
	return out, err
}

// GetAttributes reads the requested attributes of obj. Variable-length
// attributes such as CKA_EC_POINT need PKCS#11's two-call sequence, and
// miekg/pkcs11's C shim does that internally, so nil-valued templates are
// correct here. C_GetAttributeValue is a single call with no operation
// state, so a read lock is enough.
func (a *pkcs11Adapter) GetAttributes(ctx context.Context, s *Session, obj ObjectHandle, types []AttributeType) ([]Attribute, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if err := s.touch(); err != nil {
		return nil, err
	}
	req := make([]*p11.Attribute, len(types))
	for i, t := range types {
		req[i] = p11.NewAttribute(uint(t), nil)
	}

	var out []Attribute
	err := a.withReadLock(func() error {
		attrs, err := a.ctx.GetAttributeValue(s.handle, p11.ObjectHandle(obj), req)
		if err != nil {
			return fmt.Errorf("C_GetAttributeValue: %w", err)
		}
		for _, at := range attrs {
			out = append(out, Attribute{Type: AttributeType(at.Type), Value: at.Value})
		}
		return nil
	})
	return out, err
}

// ─── Sign / Verify ───────────────────────────────────────────────────────

// Sign produces a signature over data with C_SignInit and C_Sign, in one
// part. CKM_ECDSA takes a fixed-size digest, and the CA signs digests and
// CRLs, never bulk data, so there is no C_SignUpdate path. Both calls run
// inside one locked closure. C_Sign ends the active operation on any
// error other than CKR_BUFFER_TOO_SMALL, and internal/ca.Signer opens a
// fresh session per call, so a failed signature does not leave a session
// in CKR_OPERATION_ACTIVE.
func (a *pkcs11Adapter) Sign(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data []byte) ([]byte, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if err := s.touch(); err != nil {
		return nil, err
	}
	var sig []byte
	err := a.withStateLock(func() error {
		m := []*p11.Mechanism{p11.NewMechanism(uint(mech.Type), mech.Param)}
		if err := a.ctx.SignInit(s.handle, m, p11.ObjectHandle(key)); err != nil {
			return fmt.Errorf("C_SignInit: %w", err)
		}
		out, err := a.ctx.Sign(s.handle, data)
		if err != nil {
			return fmt.Errorf("C_Sign: %w", err)
		}
		sig = out
		return nil
	})
	return sig, err
}

// Verify checks sig over data. It takes the exclusive lock although it
// uses a public key: C_VerifyInit and C_Verify leave the session in an
// active operation in between, and PKCS#11 allows one active operation
// per session. Two callers under a read lock would interleave their Init
// calls.
func (a *pkcs11Adapter) Verify(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data, sig []byte) error {
	if err := checkCtx(ctx); err != nil {
		return err
	}
	if err := s.touch(); err != nil {
		return err
	}
	return a.withStateLock(func() error {
		m := []*p11.Mechanism{p11.NewMechanism(uint(mech.Type), mech.Param)}
		if err := a.ctx.VerifyInit(s.handle, m, p11.ObjectHandle(key)); err != nil {
			return fmt.Errorf("C_VerifyInit: %w", err)
		}
		if err := a.ctx.Verify(s.handle, data, sig); err != nil {
			return fmt.Errorf("C_Verify: %w", err)
		}
		return nil
	})
}

// ─── Encrypt / Decrypt ───────────────────────────────────────────────────

// Encrypt encrypts plaintext with a symmetric key, in one part. The input
// is caller-controlled, so a very large input is bounded by token memory.
// A caller with bulk data needs the C_EncryptUpdate path, which does not
// exist here. miekg/pkcs11's C shim sizes the output buffer with the
// standard two-call sequence.
func (a *pkcs11Adapter) Encrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, plaintext []byte) ([]byte, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if err := s.touch(); err != nil {
		return nil, err
	}
	var out []byte
	err := a.withStateLock(func() error {
		m := []*p11.Mechanism{p11.NewMechanism(uint(mech.Type), mech.Param)}
		if err := a.ctx.EncryptInit(s.handle, m, p11.ObjectHandle(key)); err != nil {
			return fmt.Errorf("C_EncryptInit: %w", err)
		}
		ct, err := a.ctx.Encrypt(s.handle, plaintext)
		if err != nil {
			return fmt.Errorf("C_Encrypt: %w", err)
		}
		out = ct
		return nil
	})
	return out, err
}

func (a *pkcs11Adapter) Decrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, ciphertext []byte) ([]byte, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if err := s.touch(); err != nil {
		return nil, err
	}
	var out []byte
	err := a.withStateLock(func() error {
		m := []*p11.Mechanism{p11.NewMechanism(uint(mech.Type), mech.Param)}
		if err := a.ctx.DecryptInit(s.handle, m, p11.ObjectHandle(key)); err != nil {
			return fmt.Errorf("C_DecryptInit: %w", err)
		}
		pt, err := a.ctx.Decrypt(s.handle, ciphertext)
		if err != nil {
			return fmt.Errorf("C_Decrypt: %w", err)
		}
		out = pt
		return nil
	})
	return out, err
}

// ─── Wrap / Unwrap ───────────────────────────────────────────────────────

func (a *pkcs11Adapter) Wrap(ctx context.Context, s *Session, wrappingKey, keyToWrap ObjectHandle, mech Mechanism) ([]byte, error) {
	if err := checkCtx(ctx); err != nil {
		return nil, err
	}
	if err := s.touch(); err != nil {
		return nil, err
	}
	var out []byte
	err := a.withStateLock(func() error {
		m := []*p11.Mechanism{p11.NewMechanism(uint(mech.Type), mech.Param)}
		wrapped, err := a.ctx.WrapKey(s.handle, m, p11.ObjectHandle(wrappingKey), p11.ObjectHandle(keyToWrap))
		if err != nil {
			return fmt.Errorf("C_WrapKey: %w", err)
		}
		out = wrapped
		return nil
	})
	return out, err
}

// Unwrap imports wrapped as a new token object matching tmpl. wrapped is
// ciphertext under unwrappingKey, which never leaves the token, so it is
// not zeroed after use. The plaintext key never enters Go memory.
func (a *pkcs11Adapter) Unwrap(ctx context.Context, s *Session, unwrappingKey ObjectHandle, mech Mechanism, wrapped []byte, tmpl []Attribute) (ObjectHandle, error) {
	if err := checkCtx(ctx); err != nil {
		return 0, err
	}
	if err := s.touch(); err != nil {
		return 0, err
	}
	p11Template := toP11Attributes(tmpl)

	var handle p11.ObjectHandle
	err := a.withStateLock(func() error {
		m := []*p11.Mechanism{p11.NewMechanism(uint(mech.Type), mech.Param)}
		h, err := a.ctx.UnwrapKey(s.handle, m, p11.ObjectHandle(unwrappingKey), wrapped, p11Template)
		if err != nil {
			return fmt.Errorf("C_UnwrapKey: %w", err)
		}
		handle = h
		return nil
	})
	if err != nil {
		return 0, err
	}
	return ObjectHandle(handle), nil
}

// ─── Adapter teardown ────────────────────────────────────────────────────

// Close stops the janitor, force-closes every open session, and finalizes
// the module. After Close, every other method returns ErrAdapterClosed.
func (a *pkcs11Adapter) Close() error {
	// sync.Once: close(a.janitorStop) must run once, and two concurrent
	// Close callers could both pass an a.closed check first.
	a.closeOnce.Do(func() {
		close(a.janitorStop)
		<-a.janitorDone

		// Logging out before C_Finalize leaves the token in a known state.
		a.loginMu.Lock()
		_ = a.logoutTokenLocked()
		a.loginMu.Unlock()

		a.sessMu.Lock()
		handles := make([]p11.SessionHandle, 0, len(a.sessions))
		for h, s := range a.sessions {
			s.markClosed()
			handles = append(handles, h)
		}
		a.sessions = make(map[p11.SessionHandle]*Session)
		a.sessMu.Unlock()

		a.mu.Lock()
		defer a.mu.Unlock()
		for _, h := range handles {
			_ = a.ctx.CloseSession(h)
		}
		a.ctx.Finalize()
		a.ctx.Destroy()
		a.closed = true
	})
	return nil
}

// ─── Background session janitor ─────────────────────────────────────────

// janitor force-closes sessions past their idle timeout or max TTL, so a
// token session slot is reclaimed even when the caller never touches the
// session again.
func (a *pkcs11Adapter) janitor(interval time.Duration) {
	defer close(a.janitorDone)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-a.janitorStop:
			return
		case <-t.C:
			a.sweepExpired()
		}
	}
}

func (a *pkcs11Adapter) sweepExpired() {
	a.sessMu.Lock()
	var expired []p11.SessionHandle
	for h, s := range a.sessions {
		if s.expired() {
			s.markClosed()
			expired = append(expired, h)
			delete(a.sessions, h)
		}
	}
	a.sessMu.Unlock()

	for _, h := range expired {
		_ = a.withStateLock(func() error { return a.ctx.CloseSession(h) })
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────

func toP11Attributes(attrs []Attribute) []*p11.Attribute {
	out := make([]*p11.Attribute, len(attrs))
	for i, a := range attrs {
		out[i] = p11.NewAttribute(uint(a.Type), a.Value)
	}
	return out
}

// zeroizeBytes overwrites b in place. Safe on nil and empty slices. This
// is a best-effort wipe of a Go-heap buffer: the runtime may have copied
// the bytes already. SecurePIN keeps the copy this package can wipe for
// certain.
func zeroizeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func resolveID(id []byte) ([]byte, error) {
	if len(id) > 0 {
		return id, nil
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("pkcs11: generating key id: %w", err)
	}
	return b, nil
}

// ecCurveOID returns the DER-encoded OID CKA_EC_PARAMS expects for the
// curve (SEC 2, RFC 5480).
func ecCurveOID(c ECCurve) ([]byte, error) {
	switch c {
	case P256:
		return []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, nil
	case P384:
		return []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}, nil
	case P521:
		return []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}, nil
	default:
		return nil, ErrUnsupportedCurve
	}
}
