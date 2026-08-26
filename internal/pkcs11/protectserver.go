package pkcs11

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	p11 "github.com/miekg/pkcs11"
)

// psJanitorInterval mirrors SoftHSM2Adapter's janitorInterval — see that
// constant's comment for why the sweep timing itself is not exercised by
// the test suite.
const psJanitorInterval = 30 * time.Second

// ProtectServerAdapter implements VendorAdapter against Thales ProtectServer
// HSMs via the ProtectToolkit-C PKCS#11 module.
//
// This is the second, independently-written vendor adapter — the proof that
// VendorAdapter is a real abstraction and not a SoftHSM2-shaped guess (see
// "Why two adapters rather than one" in docs/phases/phase-1-pkcs11-core.md).
// Its body is, deliberately, nearly identical to SoftHSM2Adapter's: the
// divergence log below is the record of what was actually found to differ,
// and sub-task 1.8 extracts the shared remainder into a common base only
// now that this second implementation exists to compare against — extracting
// it first would have meant guessing which parts were genuinely shared.
//
// # Why this adapter exists alongside SoftHSM2Adapter
//
// SoftHSM2 carries CI and reproducibility: it needs no hardware and no
// proprietary SDK, so anyone can run the full suite. But an abstraction that
// has only ever been implemented once is a guess. ProtectServer is a real
// vendor implementation, and one interface surviving both unchanged is the
// evidence the design actually generalizes.
//
// # Verified environment
//
// Confirmed against the maintainer's own ProtectToolkit installation;
// docs/protectserver-setup.md carries the setup steps.
//
//   - Product: Thales ProtectToolkit-C 7.3.3, software emulation mode
//     (token model "SW:SWEMUL"). ProtectServer is the HSM family;
//     ProtectToolkit is the SDK that drives it, and libctsw.so is its
//     software-only emulation of one.
//   - Module: /opt/safenet/protecttoolkit7/ptk/lib/libctsw.so — dlopen-able
//     directly, with no LD_LIBRARY_PATH set, because the library resolves
//     only against libdl/libpthread/libc.
//   - Slots: slot 1 holds "AdminToken (0000)"; slot 0 is the working user
//     token, labelled and PIN-initialized by the operator steps in
//     docs/protectserver-setup.md before this adapter can find it.
//
// # Divergences from SoftHSM2
//
// Record every vendor-specific behaviour discovered here. This list is what
// sub-task 1.8 reads when deciding which plumbing is genuinely shared and
// which only looked shared. Do not resolve a divergence by widening the
// VendorAdapter interface; resolve it inside this adapter (CLAUDE.md: vendor
// quirks never leak into the interface).
//
//	WORKS UNCHANGED: Workspaces, OpenSession, CloseSession, Login (CKU_USER),
//	Logout, GenerateRandom, GenerateKeyPair (EC P-256), GenerateSecretKey
//	(AES), Sign and Verify (CKM_ECDSA, 64-byte r||s as expected), Encrypt/
//	Decrypt (CKM_AES_CBC_PAD), Wrap/Unwrap (CKM_AES_KEY_WRAP), FindObjects,
//	GetAttributes, Close. CKA_EC_POINT comes back DER-wrapped
//	(0x04 0x41 || point), the same as SoftHSM2. Confirmed by the conformance
//	suite (TestConformance/ProtectServer) passing unchanged against this
//	adapter.
//
//	DIVERGES — all-zero ECDSA digest: C_Sign accepts a digest of all zero
//	bytes and returns a signature, but C_Verify then rejects that signature
//	with CKR_SIGNATURE_INVALID (0xC0). SoftHSM2 2.6.1 accepts it. Reproduced
//	at 32 and 20 bytes; a non-zero digest of either length verifies fine on
//	both. Almost certainly a deliberate guard: an all-zero digest converts to
//	the ECDSA scalar e = 0, a degenerate case some implementations refuse on
//	the verify path while permitting on the sign path.
//
//	This divergence is benign for real use — a digest of an actual message is
//	never all-zero, since producing one would be a preimage break — so it
//	needs no workaround. It is recorded because it is a genuine behavioural
//	difference, and because of how it was found: a first diagnostic used
//	make([]byte, 32) as a stand-in digest and reported "ProtectServer cannot
//	verify" for two commits before a real digest showed Verify working
//	normally. Degenerate test vectors produce degenerate conclusions — the
//	conformance suite uses only real digests and non-degenerate vectors for
//	exactly this reason.
type ProtectServerAdapter struct {
	mu     sync.RWMutex
	ctx    *p11.Ctx
	closed bool

	sessMu   sync.Mutex
	sessions map[p11.SessionHandle]*Session

	janitorStop chan struct{}
	janitorDone chan struct{}
	closeOnce   sync.Once
}

// NewProtectServerAdapter loads and initializes the ProtectToolkit PKCS#11
// module at modulePath (e.g. /opt/safenet/protecttoolkit7/ptk/lib/libctsw.so
// for software emulation, or libcthsm.so for a hardware ProtectServer).
func NewProtectServerAdapter(modulePath string) (*ProtectServerAdapter, error) {
	ctx := p11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: failed to load module %q", modulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: C_Initialize: %w", err)
	}

	a := &ProtectServerAdapter{
		ctx:         ctx,
		sessions:    make(map[p11.SessionHandle]*Session),
		janitorStop: make(chan struct{}),
		janitorDone: make(chan struct{}),
	}
	go a.janitor(psJanitorInterval)
	return a, nil
}

func (a *ProtectServerAdapter) withStateLock(fn func() error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrAdapterClosed
	}
	return fn()
}

func (a *ProtectServerAdapter) withReadLock(fn func() error) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return ErrAdapterClosed
	}
	return fn()
}

// ─── Workspaces ─────────────────────────────────────────────────────────

// Workspaces lists the ProtectServer tokens visible through the module.
func (a *ProtectServerAdapter) Workspaces(ctx context.Context) ([]Workspace, error) {
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

// OpenSession opens a session against ws, bounded by opts.
func (a *ProtectServerAdapter) OpenSession(ctx context.Context, ws Workspace, opts SessionOptions) (*Session, error) {
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

// CloseSession releases the underlying PKCS#11 session. Idempotent.
func (a *ProtectServerAdapter) CloseSession(ctx context.Context, s *Session) error {
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

// Login authenticates the session as the given Role. pin is consumed:
// callers must not reuse it afterward (see SecurePIN).
func (a *ProtectServerAdapter) Login(ctx context.Context, s *Session, pin []byte, role Role) error {
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

// Logout drops the session's authentication.
func (a *ProtectServerAdapter) Logout(ctx context.Context, s *Session) error {
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

// GenerateKeyPair creates an asymmetric (EC) key pair on the HSM. The
// private key never leaves the HSM; only its handle is returned.
func (a *ProtectServerAdapter) GenerateKeyPair(ctx context.Context, s *Session, req KeyPairRequest) (KeyPairHandle, error) {
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

// GenerateSecretKey creates a symmetric (AES) key on the HSM.
func (a *ProtectServerAdapter) GenerateSecretKey(ctx context.Context, s *Session, req SecretKeyRequest) (ObjectHandle, error) {
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

// GenerateRandom returns n bytes from the HSM's RNG.
func (a *ProtectServerAdapter) GenerateRandom(ctx context.Context, s *Session, n int) ([]byte, error) {
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

// FindObjects returns handles for objects matching tmpl.
func (a *ProtectServerAdapter) FindObjects(ctx context.Context, s *Session, tmpl []Attribute) ([]ObjectHandle, error) {
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

// GetAttributes reads the requested attributes off obj.
func (a *ProtectServerAdapter) GetAttributes(ctx context.Context, s *Session, obj ObjectHandle, types []AttributeType) ([]Attribute, error) {
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

// Sign produces a signature over data with an asymmetric key.
func (a *ProtectServerAdapter) Sign(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data []byte) ([]byte, error) {
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

// Verify checks sig over data with an asymmetric key.
func (a *ProtectServerAdapter) Verify(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, data, sig []byte) error {
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

// Encrypt encrypts plaintext with a symmetric key.
func (a *ProtectServerAdapter) Encrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, plaintext []byte) ([]byte, error) {
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

// Decrypt decrypts ciphertext with a symmetric key.
func (a *ProtectServerAdapter) Decrypt(ctx context.Context, s *Session, key ObjectHandle, mech Mechanism, ciphertext []byte) ([]byte, error) {
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

// Wrap exports keyToWrap encrypted under wrappingKey; the plaintext key
// material never leaves the HSM unencrypted.
func (a *ProtectServerAdapter) Wrap(ctx context.Context, s *Session, wrappingKey, keyToWrap ObjectHandle, mech Mechanism) ([]byte, error) {
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

// Unwrap imports wrapped as a new HSM object matching tmpl, decrypting it
// under unwrappingKey inside the HSM.
func (a *ProtectServerAdapter) Unwrap(ctx context.Context, s *Session, unwrappingKey ObjectHandle, mech Mechanism, wrapped []byte, tmpl []Attribute) (ObjectHandle, error) {
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
func (a *ProtectServerAdapter) Close() error {
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

func (a *ProtectServerAdapter) janitor(interval time.Duration) {
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

func (a *ProtectServerAdapter) sweepExpired() {
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

// Compile-time proof that a second, independent vendor satisfies the same
// VendorAdapter contract. If a future change to the interface is shaped
// around SoftHSM2's behaviour alone, this assertion is what breaks the
// build.
var _ VendorAdapter = (*ProtectServerAdapter)(nil)
