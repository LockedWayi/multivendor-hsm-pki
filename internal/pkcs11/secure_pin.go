package pkcs11

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import "unsafe"

// SecurePIN holds a PIN in a buffer allocated with C.malloc. The Go GC does
// not move or copy that buffer, so Zeroize can overwrite it and know that
// copy is gone.
//
// It is not the only copy. withGoString hands the PIN to miekg/pkcs11 as a
// Go string. Login in that binding (v1.1.2) calls C.CString, which makes a
// second C buffer, and frees it after C_Login without zeroing it. That
// copy is outside this package's control. docs/threat-model.md, "PIN
// handling", records the residual and the two options.
type SecurePIN struct {
	buf unsafe.Pointer
	n   C.size_t
}

// NewSecurePIN copies pin into a new C-heap buffer and zeroes pin in
// place. pin is all-zero after this call returns.
func NewSecurePIN(pin []byte) *SecurePIN {
	n := C.size_t(len(pin))
	var buf unsafe.Pointer
	if n > 0 {
		buf = C.malloc(n)
		// A C-heap buffer does not move, so Zeroize can reach it later.
		// nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
		C.memcpy(buf, unsafe.Pointer(&pin[0]), n)
	}
	for i := range pin {
		pin[i] = 0
	}
	return &SecurePIN{buf: buf, n: n}
}

// withGoString calls fn with a Go string that aliases the C buffer through
// unsafe.String, so no Go-heap copy is made here. fn must not keep the
// string: Zeroize frees the buffer. The binding's Login still makes its
// own C copy; see the type comment.
func (p *SecurePIN) withGoString(fn func(string) error) error {
	if p.n == 0 {
		return fn("")
	}
	// nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block
	s := unsafe.String((*byte)(p.buf), int(p.n))
	return fn(s)
}

// wipe overwrites the buffer without freeing it. Tests read the buffer
// after wipe to check the overwrite. Reading it after free would be a
// use-after-free.
func (p *SecurePIN) wipe() {
	if p.buf != nil {
		C.memset(p.buf, 0, p.n)
	}
}

// Zeroize overwrites the buffer and frees it. Safe to call more than once,
// and on a PIN that was never populated.
func (p *SecurePIN) Zeroize() {
	if p.buf == nil {
		return
	}
	p.wipe()
	C.free(p.buf)
	p.buf = nil
	p.n = 0
}
