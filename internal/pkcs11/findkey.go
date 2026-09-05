package pkcs11

import (
	"context"
	"errors"
	"fmt"
)

// ErrKeyNotFound reports that no object matched the class and label asked
// for. It is a distinct error because callers routinely need to tell "this
// key is not here yet" from "the search failed" — provisioning refuses to
// proceed when a label is already taken, and loading refuses to proceed
// when it is not.
var ErrKeyNotFound = errors.New("pkcs11: no key object found")

// ErrAmbiguousLabel reports that more than one object matched. It is
// separate from ErrKeyNotFound because the two demand opposite responses
// from an operator: one means "create it", the other means "work out which
// of these you meant, because nobody can".
var ErrAmbiguousLabel = errors.New("pkcs11: label matches more than one object")

// FindKeyByLabel returns the single object of the given class carrying the
// given CKA_LABEL in session s, and refuses to guess.
//
// The refusal is the point, and it is the identity rule in code. PKCS#11
// defines CKA_LABEL as a description and nowhere requires it to be unique,
// so a label search returning several objects is a normal thing for a token
// to do and never a decidable question for the caller: picking the first
// match hands the choice to enumeration order, which is nobody's decision
// and is not stable between runs or between vendors. Two objects that a
// label cannot distinguish must be distinguished by something else, by a
// human, before anything signs with either.
//
// A handle is only valid inside the session that obtained it, so this is
// called fresh per session rather than cached — see the doc comment on
// Session.
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
//
// Provisioning uses it as a precondition rather than discovering the
// conflict mid-flight: generating a key pair is irreversible, and finding
// out afterwards that the label was taken leaves an operator to clean up a
// token by hand. An ambiguous label is not free — it is
// the most taken a label can be.
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
