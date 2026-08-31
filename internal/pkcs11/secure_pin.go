package pkcs11

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import "unsafe"

// SecurePIN holds a PIN or passphrase in a C-heap buffer instead of Go's
// garbage-collected heap.
//
// Go strings are immutable by language contract, so once a secret becomes a
// Go string there is no supported way to force the runtime to forget it —
// the backing bytes may already have been copied, and overwriting them
// after the fact through unsafe (a common but naive pattern) does not
// change that. See docs/phases/phase-1-pkcs11-core.md, "PIN zeroize
// method", for the full reasoning and the rejected alternative.
//
// A C.malloc'd buffer is memory the Go GC never owns, moves, or copies, so
// it is memory we can positively, deterministically zero. That is the
// property this type exists for.
type SecurePIN struct {
	buf unsafe.Pointer
	n   C.size_t
}

// NewSecurePIN copies pin into a new C-heap buffer and zeroes pin in place.
// pin is unusable (all-zero) after this call returns; the C-heap copy is
// the only remaining copy this package is responsible for.
func NewSecurePIN(pin []byte) *SecurePIN {
	n := C.size_t(len(pin))
	var buf unsafe.Pointer
	if n > 0 {
		buf = C.malloc(n)
		C.memcpy(buf, unsafe.Pointer(&pin[0]), n)
	}
	for i := range pin {
		pin[i] = 0
	}
	return &SecurePIN{buf: buf, n: n}
}

// withGoString invokes fn with a Go string that ALIASES the C buffer's
// bytes directly via unsafe.String (Go 1.20+) — this does not allocate a
// second, Go-heap-owned copy of the PIN. fn must not retain the string
// beyond its own call, since the buffer is freed by Zeroize.
func (p *SecurePIN) withGoString(fn func(string) error) error {
	if p.n == 0 {
		return fn("")
	}
	s := unsafe.String((*byte)(p.buf), int(p.n))
	return fn(s)
}

// wipe overwrites the C-heap buffer with zeros without freeing it. Split
// out from Zeroize so tests can verify the overwrite happened by reading
// the buffer afterward — reading it post-free would be a use-after-free
// read into memory glibc's allocator may have already reused for its own
// free-list bookkeeping, which proves nothing about our memset.
func (p *SecurePIN) wipe() {
	if p.buf != nil {
		C.memset(p.buf, 0, p.n)
	}
}

// Zeroize overwrites the C-heap buffer with zeros and frees it. Safe to
// call more than once, and safe to call on a PIN that was never populated.
func (p *SecurePIN) Zeroize() {
	if p.buf == nil {
		return
	}
	p.wipe()
	C.free(p.buf)
	p.buf = nil
	p.n = 0
}
