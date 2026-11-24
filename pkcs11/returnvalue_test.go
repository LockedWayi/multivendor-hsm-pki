package pkcs11

import (
	"errors"
	"fmt"
	"testing"

	p11 "github.com/miekg/pkcs11"
)

// A module's refusal, converted at the boundary, matches the package's
// ReturnValue, still matches the binding's type for code that tests for
// that, and reads exactly as it did before the conversion.
func TestFromModule_AddsTheCodeAndKeepsTheMessage(t *testing.T) {
	raw := fmt.Errorf("C_Login: %w", p11.Error(p11.CKR_PIN_INCORRECT))
	err := fromModule(raw)

	if !errors.Is(err, RVPINIncorrect) {
		t.Fatalf("%v does not match RVPINIncorrect", err)
	}
	if errors.Is(err, RVPINLocked) {
		t.Fatalf("%v matches a code it does not carry", err)
	}
	var ckr p11.Error
	if !errors.As(err, &ckr) || ckr != p11.CKR_PIN_INCORRECT {
		t.Fatalf("%v no longer carries the binding's error", err)
	}
	if err.Error() != raw.Error() {
		t.Fatalf("message changed: %q, was %q", err, raw)
	}
	if rv, ok := ReturnValueOf(fmt.Errorf("wrapped again: %w", err)); !ok || rv != RVPINIncorrect {
		t.Fatalf("ReturnValueOf through a further wrap = %v, %v", rv, ok)
	}
	if again := fromModule(err); again != err {
		t.Fatal("converting twice wrapped the error again")
	}
}

func TestFromModule_LeavesOtherErrorsAlone(t *testing.T) {
	if fromModule(nil) != nil {
		t.Fatal("fromModule(nil) is not nil")
	}
	if err := fromModule(ErrAdapterClosed); err != ErrAdapterClosed {
		t.Fatalf("fromModule changed an error without a code: %v", err)
	}
	if _, ok := ReturnValueOf(ErrSessionExpired); ok {
		t.Fatal("ReturnValueOf found a code in an error that has none")
	}
}

// The text is the binding's, so a log line reads the same whichever type
// carried the code.
func TestReturnValue_ErrorIsTheBindingsText(t *testing.T) {
	for _, rv := range []ReturnValue{RVPINIncorrect, RVDataInvalid, ReturnValue(0x80000123)} {
		if rv.Error() != p11.Error(rv).Error() {
			t.Fatalf("%#x reads %q, the binding %q", uint(rv), rv.Error(), p11.Error(rv).Error())
		}
	}
	if !errors.Is(fromModule(p11.Error(0x80000123)), ReturnValue(0x80000123)) {
		t.Fatal("a vendor-defined code without a constant is not matched by value")
	}
}

// ReturnValueOf reads the binding's error too, for an error inside this
// package that has not crossed onModuleThread yet.
func TestReturnValueOf_ReadsTheBindingsErrorBeforeConversion(t *testing.T) {
	rv, ok := ReturnValueOf(fmt.Errorf("C_CloseSession: %w", p11.Error(p11.CKR_SESSION_HANDLE_INVALID)))
	if !ok || rv != RVSessionHandleInvalid {
		t.Fatalf("ReturnValueOf = %v, %v", rv, ok)
	}
}
