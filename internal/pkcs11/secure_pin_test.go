package pkcs11

import (
	"testing"
	"unsafe"
)

func TestNewSecurePIN_ZeroesCallerSlice(t *testing.T) {
	pin := []byte("1234abcd")
	secure := NewSecurePIN(pin)
	defer secure.Zeroize()

	for i, b := range pin {
		if b != 0 {
			t.Fatalf("caller slice not zeroed at index %d: got %x", i, b)
		}
	}
}

func TestSecurePIN_WithGoStringDeliversContent(t *testing.T) {
	want := "sup3r-secret-pin"
	pin := []byte(want)
	secure := NewSecurePIN(pin)
	defer secure.Zeroize()

	var got string
	err := secure.withGoString(func(s string) error {
		got = s
		return nil
	})
	if err != nil {
		t.Fatalf("withGoString returned error: %v", err)
	}
	if got != want {
		t.Fatalf("withGoString content = %q, want %q", got, want)
	}
}

func TestSecurePIN_EmptyPIN(t *testing.T) {
	secure := NewSecurePIN(nil)
	defer secure.Zeroize()

	var got string
	if err := secure.withGoString(func(s string) error { got = s; return nil }); err != nil {
		t.Fatalf("withGoString returned error: %v", err)
	}
	if got != "" {
		t.Fatalf("withGoString content = %q, want empty", got)
	}
}

func TestSecurePIN_WipeZeroesBuffer(t *testing.T) {
	pin := []byte("wipe-me-please")
	secure := NewSecurePIN(pin)
	defer secure.Zeroize()

	// White-box: read the C buffer directly before and after wipe() to
	// confirm the memory itself is overwritten, not just unreferenced.
	// This reads the buffer while it is still allocated (before free) —
	// reading it post-free would be a use-after-free read into memory
	// glibc's allocator may have already reused for its own free-list
	// bookkeeping, which would prove nothing about our memset.
	n := int(secure.n)
	buf := secure.buf
	before := make([]byte, n)
	for i := 0; i < n; i++ {
		before[i] = *(*byte)(unsafe.Add(buf, i))
	}
	if string(before) != "wipe-me-please" {
		t.Fatalf("C buffer did not contain the PIN before wipe: %q", before)
	}

	secure.wipe()

	after := make([]byte, n)
	for i := 0; i < n; i++ {
		after[i] = *(*byte)(unsafe.Add(buf, i))
	}
	for i, b := range after {
		if b != 0 {
			t.Fatalf("C buffer not zeroed at index %d after wipe: %x", i, b)
		}
	}
}

func TestSecurePIN_ZeroizeNilsPointer(t *testing.T) {
	secure := NewSecurePIN([]byte("nil-me"))
	secure.Zeroize()
	if secure.buf != nil {
		t.Fatal("Zeroize did not nil the buffer pointer")
	}
}

func TestSecurePIN_ZeroizeIsIdempotent(t *testing.T) {
	secure := NewSecurePIN([]byte("abc"))
	secure.Zeroize()
	secure.Zeroize() // must not panic or double-free
}

func TestSecurePIN_ZeroizeOnEmpty(t *testing.T) {
	secure := NewSecurePIN(nil)
	secure.Zeroize() // must not panic on a buffer that was never allocated
}
