package pkcs11

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"

	p11 "github.com/miekg/pkcs11"
)

// janitorInterval is how often the background sweep looks for sessions
// past their idle timeout or max TTL and force-closes them, so an HSM
// session slot is reclaimed even if nothing ever calls the session again.
//
// Not exercised on its own timing in the test suite: SoftHSM2's C_Initialize
// is a one-per-process resource (see TestZZZAdapterClose_RejectsFurtherUse),
// so a test cannot spin up a second, short-interval adapter alongside the
// shared test adapter to observe a real sweep. touch()'s lazy expiry check —
// which is exercised — enforces the same idle-timeout/max-TTL contract on
// every call; the janitor only affects how promptly an *unused* session's
// HSM slot is reclaimed in the background.
const janitorInterval = 30 * time.Second

// SoftHSM2Adapter implements VendorAdapter against SoftHSM2's PKCS#11
// module. It is the only backend Phase 1 requires actually running
// (docs/phases/phase-1-pkcs11-core.md); nShield/Luna/ProtectServer adapters
// implement the same VendorAdapter interface later without callers
// changing (Phase 7).
//
// Each SoftHSM2Adapter owns its own *p11.Ctx and its own lock — this is
// deliberately not a process-wide singleton. A server process can hold one
// adapter instance per vendor, or per HSM, concurrently.
//
// Lock discipline mirrors the PKCS#11 spec's own concurrency rules:
//   - withStateLock (full Lock) — required for multi-step stateful call
//     sequences on a session (FindObjectsInit/FindObjects/FindObjectsFinal,
//     SignInit/Sign, Login, GenerateKeyPair, ...), which the spec requires
//     be serialized.
//   - withReadLock (RLock) — used only for single-call, spec-safe-to-run-
//     concurrently operations (GetAttributeValue, GenerateRandom).
type SoftHSM2Adapter struct {
	mu     sync.RWMutex
	ctx    *p11.Ctx
	closed bool

	sessMu   sync.Mutex
	sessions map[p11.SessionHandle]*Session

	janitorStop chan struct{}
	janitorDone chan struct{}
	closeOnce   sync.Once
}

// NewSoftHSM2Adapter loads and initializes the PKCS#11 module at modulePath
// (e.g. /usr/lib/softhsm/libsofthsm2.so).
func NewSoftHSM2Adapter(modulePath string) (*SoftHSM2Adapter, error) {
	ctx := p11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: failed to load module %q", modulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: C_Initialize: %w", err)
	}

	a := &SoftHSM2Adapter{
		ctx:         ctx,
		sessions:    make(map[p11.SessionHandle]*Session),
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
	}
	go a.janitor(janitorInterval)
	return a, nil
}

func (a *SoftHSM2Adapter) withStateLock(fn func() error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrAdapterClosed
	}
	return fn()
}

func (a *SoftHSM2Adapter) withReadLock(fn func() error) error {
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

func (a *SoftHSM2Adapter) Workspaces(ctx context.Context) ([]Workspace, error) {
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
				SlotID:  id,
				Label:   strings.TrimRight(ti.Label, " "),
				Present: true,
			})
		}
		return nil
	})
	return out, err
}

// ─── Session lifecycle ─────────────────────────────────────────────────

func (a *SoftHSM2Adapter) OpenSession(ctx context.Context, ws Workspace, opts SessionOptions) (*Session, error) {
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

func (a *SoftHSM2Adapter) CloseSession(ctx context.Context, s *Session) error {
	s.markClosed()
	a.sessMu.Lock()
	delete(a.sessions, s.handle)
	a.sessMu.Unlock()
	return a.withStateLock(func() error {
		if err := a.ctx.CloseSession(s.handle); err != nil {
			return fmt.Errorf("C_CloseSession: %w", err)
		}
		return nil
	})
}

// ─── Login / Logout ─────────────────────────────────────────────────────

func (a *SoftHSM2Adapter) Login(ctx context.Context, s *Session, pin []byte, role Role) error {
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

func (a *SoftHSM2Adapter) Logout(ctx context.Context, s *Session) error {
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

func (a *SoftHSM2Adapter) GenerateKeyPair(ctx context.Context, s *Session, req KeyPairRequest) (KeyPairHandle, error) {
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
		p11.NewAttribute(p11.CKA_SENSITIVE, req.Sensitive),
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

func (a *SoftHSM2Adapter) GenerateSecretKey(ctx context.Context, s *Session, req SecretKeyRequest) (ObjectHandle, error) {
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

func (a *SoftHSM2Adapter) GenerateRandom(ctx context.Context, s *Session, n int) ([]byte, error) {
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

func (a *SoftHSM2Adapter) FindObjects(ctx context.Context, s *Session, tmpl []Attribute) ([]ObjectHandle, error) {
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
		for {
			batch, more, err := a.ctx.FindObjects(s.handle, 50)
			if err != nil {
				return fmt.Errorf("C_FindObjects: %w", err)
			}
			for _, h := range batch {
				out = append(out, ObjectHandle(h))
			}
			if !more {
				break
			}
		}
		return nil
	})
	return out, err
}

func (a *SoftHSM2Adapter) GetAttributes(ctx context.Context, s *Session, obj ObjectHandle, types []AttributeType) ([]Attribute, error) {
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

func (a *SoftHSM2Adapter) Sign(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data []byte) ([]byte, error) {
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

func (a *SoftHSM2Adapter) Verify(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data, sig []byte) error {
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

func (a *SoftHSM2Adapter) Encrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, plaintext []byte) ([]byte, error) {
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

func (a *SoftHSM2Adapter) Decrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, ciphertext []byte) ([]byte, error) {
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

func (a *SoftHSM2Adapter) Wrap(ctx context.Context, s *Session, wrappingKey, keyToWrap ObjectHandle, mech Mechanism) ([]byte, error) {
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

func (a *SoftHSM2Adapter) Unwrap(ctx context.Context, s *Session, unwrappingKey ObjectHandle, mech Mechanism, wrapped []byte, tmpl []Attribute) (ObjectHandle, error) {
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

// Close stops the session janitor, force-closes every still-open session,
// and finalizes/destroys the PKCS#11 module. After Close returns, every
// other method on this adapter returns ErrAdapterClosed.
func (a *SoftHSM2Adapter) Close() error {
	// sync.Once, not an a.closed check inside the locked section below:
	// close(a.janitorStop) itself must run exactly once, and checking
	// a.closed first would still race two concurrent Close callers into
	// both reaching the channel close before either sets the flag.
	a.closeOnce.Do(func() {
		close(a.janitorStop)
		<-a.janitorDone

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

// janitor force-closes sessions past their idle timeout or max TTL, so an
// HSM session slot is reclaimed even if the caller never touches that
// session again (e.g. an abandoned client). See SessionOptions.
func (a *SoftHSM2Adapter) janitor(interval time.Duration) {
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

func (a *SoftHSM2Adapter) sweepExpired() {
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

// ecCurveOID returns the DER-encoded OID PKCS#11's CKA_EC_PARAMS expects
// for the given curve. These OIDs are from the standard curve registry
// (SEC 2 / RFC 5480), not vendor-specific.
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

var _ VendorAdapter = (*SoftHSM2Adapter)(nil)
