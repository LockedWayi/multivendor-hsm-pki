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

// janitorInterval is how often the background sweep looks for sessions
// past their idle timeout or max TTL and force-closes them, so an HSM
// session slot is reclaimed even if nothing ever calls the session again.
//
// Not exercised on its own timing in the test suite: PKCS#11's
// C_Initialize is a one-per-module-per-process resource (see
// AdapterClose_RejectsFurtherUse in conformance_test.go), so a test cannot
// spin up a second, short-interval adapter alongside the shared test
// adapter to observe a real sweep. touch()'s lazy expiry check — which is
// exercised — enforces the same idle-timeout/max-TTL contract on every
// call; the janitor only affects how promptly an *unused* session's HSM
// slot is reclaimed in the background.
const janitorInterval = 30 * time.Second

// pkcs11Adapter is the standard-PKCS#11 plumbing shared by every
// VendorAdapter implementation in this package. It is unexported: callers
// only ever see SoftHSM2Adapter or ProtectServerAdapter, each a thin named
// type embedding *pkcs11Adapter (docs/phases/phase-1-pkcs11-core.md
// sub-task 1.8).
//
// This type did not exist until the second vendor adapter (ProtectServer)
// was written and run against real hardware. Extracting it earlier, from
// SoftHSM2Adapter alone, would have meant guessing which parts of a
// PKCS#11 implementation are genuinely vendor-independent — the classic
// premature-abstraction mistake this project is explicitly built to avoid
// (see "Why two adapters rather than one" and "Shared-core extraction is
// sequenced after the second adapter" in the phase file). Sub-task 1.7's
// conformance suite settled the question empirically: every operation
// exercised — session lifecycle, key generation, sign/verify, encrypt/
// decrypt, wrap/unwrap, generate random, find/get-attributes, close —
// passed unchanged against both SoftHSM2 and ProtectServer. The one real
// divergence found (ProtectToolkit's C_Verify rejecting an all-zero
// digest, see protectserver.go) is a fact about HSM *behavior*, not a
// difference in what code must run to reach it — so it needed a code
// comment and a documented boundary, not a vendor-specific branch here.
// The result: as of this extraction, there are no vendor-specific
// overrides at all. That absence is itself the finding sub-task 1.8's
// checklist asks for, not a gap in the refactor.
//
// Each pkcs11Adapter owns its own *p11.Ctx and its own lock — this is
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
type pkcs11Adapter struct {
	mu     sync.RWMutex
	ctx    *p11.Ctx
	closed bool

	sessMu   sync.Mutex
	sessions map[p11.SessionHandle]*Session

	// Anchor login state. See tokenlogin.go for the model and why the
	// anchor session is a raw handle rather than a *Session.
	loginMu         sync.Mutex
	anchorSession   p11.SessionHandle
	anchorWorkspace Workspace
	tokenLoggedIn   bool

	janitorStop chan struct{}
	janitorDone chan struct{}
	closeOnce   sync.Once
}

// newPKCS11Adapter loads and initializes the PKCS#11 module at modulePath
// and starts its session janitor. Shared by every vendor's exported
// constructor (NewSoftHSM2Adapter, NewProtectServerAdapter, ...).
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

// withReadLock runs fn under a shared lock. It is used only for
// session-scoped single-call operations: C_GetAttributeValue and
// C_GenerateRandom.
//
// Two separate cautions apply before adding a third caller, and they fail
// in different ways:
//
// First, Go cannot prove fn is read-only. A future change that puts a
// multi-step sequence (an *Init call and its follow-up) inside fn would
// compile, pass a casual review, and reintroduce exactly the cross-session
// operation-state interleaving withStateLock exists to prevent. If the
// operation has an *Init step, it needs withStateLock.
//
// Second — and this one is not a code-review problem but a vendor
// problem — "read-only by the spec" does not imply "safe to call
// concurrently on every token." ProtectToolkit 7.3.3 deadlocks inside
// C_GetSlotList when two threads call it at once, despite the module being
// initialized with CKF_OS_LOCKING_OK, which is precisely the flag that is
// supposed to make that safe. Workspaces was moved to this function on
// exactly that reasoning and had to be moved back; see its doc comment and
// docs/pkcs11-vendor-notes.md. The surviving callers here are session
// scoped, and a *Session is used by one caller at a time, so they do not
// exercise the module-global concurrency that broke.
//
// The practical rule: promoting a call to a read lock is a claim about a
// specific vendor's threading behaviour, not about the PKCS#11 spec, and
// it has to be tested against every backend before it is believed.
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

// Workspaces enumerates the tokens the module can see.
//
// This takes the full state lock, and that is load-bearing: it is what
// serializes C_GetSlotList across callers.
//
// The theoretical case for a read lock here is good, and was tried:
// C_GetSlotList and C_GetTokenInfo are single-call queries carrying no
// session-scoped operation state, and the module is initialized with
// CKF_OS_LOCKING_OK (miekg/pkcs11's Initialize default), which is a token
// library's contract to serialize its own internals. Under that reasoning
// two callers listing tokens should not need to block each other.
//
// ProtectToolkit 7.3.3 does not honour it. With the read lock in place,
// concurrent Workspaces callers deadlock *inside* C_GetSlotList — two
// goroutines parked in [syscall] on the cgo call, with no Go-level lock
// contention anywhere: the janitor idle, no writer waiting, nothing for
// them to be blocked on except the vendor library itself. Reproduced on
// the maintainer's own ProtectToolkit installation while reviewing this
// file; it does not reproduce in a freshly started process making only
// this call, which is why it needs the full conformance suite's
// accumulated activity ahead of it to show up (see
// docs/pkcs11-vendor-notes.md for the full write-up).
//
// So the exclusive lock stays. The cost is real and worth naming: a vendor
// module that stalls inside C_GetSlotList — plausible on a netHSM client
// whose network is down — stalls every other adapter operation too,
// because they all queue behind this same lock. That trade is accepted
// deliberately: a slow adapter is a worse failure than a deadlocked one,
// and CKF_OS_LOCKING_OK has been demonstrated here to be a promise at
// least one shipping vendor does not keep.
//
// TestConformance/*/Workspaces_ConcurrentCallsAreSafe is the regression
// guard. It passes trivially under this lock; it hangs against
// ProtectServer the moment someone switches this back to withReadLock.
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
// The session is marked unusable immediately and unconditionally — whatever
// the token reports next, no caller gets to keep using it (fail closed,
// CLAUDE.md §3.4). But it is only removed from the adapter's session map
// once the token has actually released the handle. Dropping the entry
// before knowing that would leave a session open on the token that nothing
// can ever reclaim: the janitor sweeps the map, and Close force-closes the
// map, so an entry deleted on a failed C_CloseSession is invisible to both.
// HSM session slots are a bounded resource (ProtectServer reports a
// per-token maximum of 65534), so a long-running service that leaked one
// per failure would eventually stop being able to open sessions at all.
//
// Two outcomes count as "the token no longer holds this handle" and are
// therefore safe to forget: success, and CKR_SESSION_HANDLE_INVALID (the
// token already considers the handle gone — the ordinary result of a
// double close, which this method's idempotency contract allows).
// ErrAdapterClosed is also safe: Close has already cleared the map and
// finalized the module, which releases every session the module held.
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

// isSessionHandleInvalid reports whether err is the token telling us the
// session handle is already gone.
func isSessionHandleInvalid(err error) bool {
	var p11Err p11.Error
	return errors.As(err, &p11Err) && p11Err == p11.Error(p11.CKR_SESSION_HANDLE_INVALID)
}

// ─── Login / Logout ─────────────────────────────────────────────────────

// Login authenticates the session as role.
//
// pin is consumed: it is zeroed in place before this returns, on every
// path, and callers must not reuse it (VendorAdapter.Login says the same).
// NewSecurePIN below already zeroes it as part of copying it to the C heap,
// but only once execution reaches that call — the guard clauses above it
// (cancelled context, expired session, empty PIN) would otherwise hand the
// caller back a still-readable PIN sitting in the Go heap, where this
// package can no longer deterministically wipe it. Making the wipe
// unconditional is what turns "pin is consumed" from a contract that holds
// on the success path into one that holds always (CLAUDE.md §3.1).
// zeroizeBytes is idempotent, so the double wipe on the normal path costs
// a second pass over a handful of bytes and nothing else.
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
	// Validate here rather than letting the token decide. CKA_VALUE_LEN is
	// bits/8, and integer division silently turns a wrong-but-plausible
	// request into a wrong-but-accepted key: 200 bits becomes a 25-byte
	// CKA_VALUE_LEN, which some tokens will happily create as a
	// non-standard AES key rather than reject. A negative KeyBits is worse
	// still. Rejecting the input outright is the fail-closed reading of an
	// ambiguous security parameter (CLAUDE.md §3.4), and it puts the error
	// at the caller's mistake instead of several layers down inside a
	// vendor module.
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
//
// Variable-length attributes (CKA_EC_POINT, CKA_MODULUS, a certificate
// body) need PKCS#11's two-call sequence — query ulValueLen with a NULL
// pValue, allocate, call again — and miekg/pkcs11's C shim does exactly
// that internally, so passing nil-valued attribute templates here is
// correct and CKR_BUFFER_TOO_SMALL is not reachable through this path.
// A read lock suffices: C_GetAttributeValue is a single call with no
// session-scoped operation state (contrast Verify, above).
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

// Sign produces a signature over data.
//
// # Single-part only, deliberately
//
// This calls C_SignInit + C_Sign, not the C_SignUpdate/C_SignFinal
// streaming form. That is a real constraint, not an oversight: the whole
// input is handed to the token in one call, so an enormous input would be
// bounded by token memory. It is the right shape for what this interface
// signs — CKM_ECDSA takes a fixed-size pre-computed digest (32 bytes for
// P-256), and the CA above it signs digests and CRLs, never bulk data.
// Adding a streaming path before a caller needs one would be speculative
// API surface; a caller that needs it should add it then, when its actual
// requirements are known.
//
// # On the "active operation" state
//
// PKCS#11 leaves a session in an active signing operation between
// C_SignInit and C_Sign, and a session stuck in that state rejects further
// operations with CKR_OPERATION_ACTIVE. Three things bound that exposure
// here: the two calls are adjacent inside one locked closure with no early
// return between them; the spec has C_Sign terminate the operation on any
// error other than CKR_BUFFER_TOO_SMALL, so a failed signature does not
// leave the session wedged; and internal/ca.Signer opens a fresh session
// per signing call and closes it afterward, which releases the state
// unconditionally. The residual case is miekg/pkcs11's C shim failing its
// calloc between its length-probe call and its real call (CKR_HOST_MEMORY),
// which would leave the operation active — an out-of-memory path where a
// wedged session is not the failure anyone is dealing with.
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

// Verify checks sig over data.
//
// This takes the full state lock, not a read lock, even though
// verification uses a public key and produces no persistent change. The
// lock here is not protecting key material — it is protecting the session's
// single operation slot. C_VerifyInit followed by C_Verify is a two-step
// sequence that leaves the session in an active verify operation in
// between, and PKCS#11 permits exactly one active operation per session.
// Two goroutines sharing a session under a read lock would interleave
// their Init calls and clobber each other's operation state, which
// surfaces as CKR_OPERATION_ACTIVE or, worse, one caller's C_Verify
// running against the other's key handle. "Read-only" describes the
// cryptography, not the session bookkeeping, and it is the bookkeeping
// that needs serializing.
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

// Encrypt encrypts plaintext with a symmetric key.
//
// Single-part (C_EncryptInit + C_Encrypt), with the same reasoning and the
// same active-operation bounds described on Sign — the difference being
// that Encrypt's input length is genuinely caller-controlled, so a caller
// feeding it hundreds of megabytes would hit token memory limits. This
// interface exists to exercise symmetric operations behind the vendor
// abstraction, not as a bulk data pipe; a caller with bulk data should add
// the C_EncryptUpdate/C_EncryptFinal path when it has one.
//
// The output buffer is sized correctly without caller involvement:
// miekg/pkcs11's C shim performs the standard two-call PKCS#11 sequence
// (C_Encrypt with a NULL output pointer to learn the length, allocate,
// then call again), so CKR_BUFFER_TOO_SMALL is not a failure mode this
// adapter has to handle.
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

// Unwrap imports wrapped as a new HSM object matching tmpl.
//
// wrapped is deliberately NOT zeroed after use, unlike a PIN. It is
// ciphertext: the key material inside it is protected by unwrappingKey,
// which never leaves the token, so a copy left in the Go heap discloses
// nothing an attacker could use without already holding the unwrapping key
// — at which point wiping this buffer would not have helped. Zeroing it
// would buy no confidentiality while implying a guarantee this package does
// not actually provide. The plaintext key material never enters Go memory
// at any point: it is decrypted inside the token and exists only as the
// returned ObjectHandle.
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

// Close stops the session janitor, force-closes every still-open session,
// and finalizes/destroys the PKCS#11 module. After Close returns, every
// other method on this adapter returns ErrAdapterClosed.
func (a *pkcs11Adapter) Close() error {
	// sync.Once, not an a.closed check inside the locked section below:
	// close(a.janitorStop) itself must run exactly once, and checking
	// a.closed first would still race two concurrent Close callers into
	// both reaching the channel close before either sets the flag.
	a.closeOnce.Do(func() {
		close(a.janitorStop)
		<-a.janitorDone

		// Drop the token's authentication before tearing anything else
		// down. C_Finalize would release it anyway, but logging out
		// explicitly means a shutdown leaves the token in a known state
		// rather than one that depends on the module's finalize path.
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

// janitor force-closes sessions past their idle timeout or max TTL, so an
// HSM session slot is reclaimed even if the caller never touches that
// session again (e.g. an abandoned client). See SessionOptions.
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

// zeroizeBytes overwrites b in place. Safe on nil and empty slices, and
// idempotent. This is a best-effort wipe of a Go-heap buffer: the runtime
// may already have copied the bytes elsewhere (that is precisely why
// SecurePIN keeps the authoritative copy in the C heap — see
// docs/phases/phase-1-pkcs11-core.md, "PIN zeroize method"). It removes the
// copy we can actually reach, which is strictly better than leaving it.
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
