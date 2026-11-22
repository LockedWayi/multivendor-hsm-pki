package pkcs11

import (
	"errors"

	p11 "github.com/miekg/pkcs11"
)

// ReturnValue is a CK_RV: the code a PKCS#11 function returned when it
// refused a call. Every refusal from the module that reaches a caller
// carries one, so a caller tests for a code without importing the
// binding:
//
//	if errors.Is(err, pkcs11.RVPINIncorrect) { ... }
//
// A code without a constant here is matched by value, as
// errors.Is(err, pkcs11.ReturnValue(0x80000123)) for a vendor-defined one.
// ReturnValueOf reads whichever code is there.
type ReturnValue uint

// Error is the binding's text for the code, so a message reads the same
// whichever type carries it: "pkcs11: 0xA0: CKR_PIN_INCORRECT".
func (rv ReturnValue) Error() string { return p11.Error(rv).Error() }

// The return values callers of this package have reason to test for.
const (
	RVGeneralError               = ReturnValue(p11.CKR_GENERAL_ERROR)
	RVFunctionFailed             = ReturnValue(p11.CKR_FUNCTION_FAILED)
	RVDeviceError                = ReturnValue(p11.CKR_DEVICE_ERROR)
	RVSlotIDInvalid              = ReturnValue(p11.CKR_SLOT_ID_INVALID)
	RVTokenNotPresent            = ReturnValue(p11.CKR_TOKEN_NOT_PRESENT)
	RVCryptokiAlreadyInitialized = ReturnValue(p11.CKR_CRYPTOKI_ALREADY_INITIALIZED)
	RVSessionHandleInvalid       = ReturnValue(p11.CKR_SESSION_HANDLE_INVALID)
	RVSessionClosed              = ReturnValue(p11.CKR_SESSION_CLOSED)
	RVObjectHandleInvalid        = ReturnValue(p11.CKR_OBJECT_HANDLE_INVALID)
	RVPINIncorrect               = ReturnValue(p11.CKR_PIN_INCORRECT)
	RVPINExpired                 = ReturnValue(p11.CKR_PIN_EXPIRED)
	RVPINLocked                  = ReturnValue(p11.CKR_PIN_LOCKED)
	RVUserAlreadyLoggedIn        = ReturnValue(p11.CKR_USER_ALREADY_LOGGED_IN)
	RVUserNotLoggedIn            = ReturnValue(p11.CKR_USER_NOT_LOGGED_IN)
	RVUserPINNotInitialized      = ReturnValue(p11.CKR_USER_PIN_NOT_INITIALIZED)
	RVUserTypeInvalid            = ReturnValue(p11.CKR_USER_TYPE_INVALID)
	RVMechanismInvalid           = ReturnValue(p11.CKR_MECHANISM_INVALID)
	RVAttributeReadOnly          = ReturnValue(p11.CKR_ATTRIBUTE_READ_ONLY)
	RVAttributeTypeInvalid       = ReturnValue(p11.CKR_ATTRIBUTE_TYPE_INVALID)
	RVTemplateInconsistent       = ReturnValue(p11.CKR_TEMPLATE_INCONSISTENT)
	RVKeyNotWrappable            = ReturnValue(p11.CKR_KEY_NOT_WRAPPABLE)
	RVKeyUnextractable           = ReturnValue(p11.CKR_KEY_UNEXTRACTABLE)
	RVDataInvalid                = ReturnValue(p11.CKR_DATA_INVALID)
	RVSignatureInvalid           = ReturnValue(p11.CKR_SIGNATURE_INVALID)
)

// ReturnValueOf reports the code a module returned, if err carries one.
func ReturnValueOf(err error) (ReturnValue, bool) {
	var rv ReturnValue
	if errors.As(err, &rv) {
		return rv, true
	}
	// Inside this package an error may not have crossed onModuleThread
	// yet and still be the binding's own.
	var ckr p11.Error
	if errors.As(err, &ckr) {
		return ReturnValue(ckr), true
	}
	return 0, false
}

// moduleError is a module's refusal as this package returns it: the
// message and chain unchanged, with the code added as a ReturnValue.
type moduleError struct {
	err error
	rv  ReturnValue
}

func (e *moduleError) Error() string   { return e.err.Error() }
func (e *moduleError) Unwrap() []error { return []error{e.err, e.rv} }

// fromModule adds a ReturnValue to an error that carries the binding's
// code. onModuleThread applies it to every error a module call returns.
func fromModule(err error) error {
	if err == nil {
		return nil
	}
	var rv ReturnValue
	if errors.As(err, &rv) {
		return err
	}
	var ckr p11.Error
	if !errors.As(err, &ckr) {
		return err
	}
	return &moduleError{err: err, rv: ReturnValue(ckr)}
}
