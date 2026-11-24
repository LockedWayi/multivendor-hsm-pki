package pkcs11

// SweepExpiredNow runs one janitor pass at once, for tests that need a
// session reclaimed without waiting for the janitor's interval.
func SweepExpiredNow(a VendorAdapter) {
	a.(interface{ sweepExpired() }).sweepExpired()
}

// HandleOf returns the module's handle for s.
func HandleOf(s *Session) uint { return uint(s.handle) }
