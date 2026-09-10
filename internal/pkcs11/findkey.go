package pkcs11

import (
	"context"
	"errors"
	"fmt"
)

// ErrKeyNotFound reports that no object matched the class and label.
// Provisioning refuses to proceed when a label is taken, and loading
// refuses when it is not, so callers need to tell the two apart.
var ErrKeyNotFound = errors.New("pkcs11: no key object found")

// ErrAmbiguousLabel reports that more than one object matched. The
// operator has to work out which one was meant.
var ErrAmbiguousLabel = errors.New("pkcs11: label matches more than one object")

// FindKeyByLabel returns the single object of the given class carrying the
// given CKA_LABEL in session s. PKCS#11 does not require CKA_LABEL to be
// unique, so a search can return several objects. Picking the first would
// leave the choice to enumeration order, which differs between runs and
// between vendors. Several matches are an error.
//
// The lookup is made per session and never cached. The Signer comment in
// internal/ca says why.
func FindKeyByLabel(ctx context.Context, adapter VendorAdapter, s *Session, class ObjectClass, label string) (ObjectHandle, error) {
	handles, err := adapter.FindObjects(ctx, s, []Attribute{
		NumericAttribute(AttrClass, uint64(class)),
		{Type: AttrLabel, Value: []byte(label)},
	})
	if err != nil {
		return 0, fmt.Errorf("pkcs11: FindObjects(class=%d, label=%q): %w", class, label, err)
	}
	switch len(handles) {
	case 0:
		return 0, fmt.Errorf("%w: class=%d label=%q", ErrKeyNotFound, class, label)
	case 1:
		return handles[0], nil
	default:
		return 0, fmt.Errorf("%w: %d objects with class %d and label %q, want exactly 1",
			ErrAmbiguousLabel, len(handles), class, label)
	}
}

// LabelIsFree reports whether no object of the given class carries label.
// Provisioning checks it before generating a key, because key generation
// cannot be undone. An ambiguous label is not free.
func LabelIsFree(ctx context.Context, adapter VendorAdapter, s *Session, class ObjectClass, label string) (bool, error) {
	_, err := FindKeyByLabel(ctx, adapter, s, class, label)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, ErrKeyNotFound):
		return true, nil
	default:
		return false, err
	}
}
