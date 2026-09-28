package pkcs11

import "runtime"

// moduleThread runs every call into one PKCS#11 module on one OS thread,
// for a module whose adapter declares SerializeOnOneThread.
//
// Go moves a goroutine between OS threads across cgo calls, so a single
// logical caller can reach the module from many threads over an adapter's
// life. A module that keeps per-thread state can be confused by that even
// with one caller at a time, which is what the ProtectToolkit-C emulator's
// C_OpenSession hang looked like: 6 hangs in 144 whole-suite runs driven
// from whichever thread Go scheduled, 0 in 104 with every call on this
// thread. That is consistent with a thread-affinity cause and is not proof
// of one; tools/hang-tally.sh keeps counting, so a declaration that does
// not help shows up as hangs.
//
// The cost is concurrency: calls run one at a time, whatever lock the
// caller holds, so a module that declares this gains nothing from a shared
// lock.
type moduleThread struct {
	calls chan func()
	done  chan struct{}
}

func newModuleThread() *moduleThread {
	m := &moduleThread{calls: make(chan func()), done: make(chan struct{})}
	go func() {
		// Never unlocked: the goroutine, and with it every module call,
		// keeps this thread until stop, and the thread exits with it.
		runtime.LockOSThread()
		defer close(m.done)
		for fn := range m.calls {
			fn()
		}
	}()
	return m
}

// run executes fn on the module thread and waits for it. A panic in fn is
// recovered there and raised again in the caller's goroutine, so it
// unwinds the caller as it would have inline instead of ending the
// process from a goroutine nobody can recover in.
func (m *moduleThread) run(fn func()) {
	var panicked any
	finished := make(chan struct{})
	m.calls <- func() {
		defer close(finished)
		defer func() { panicked = recover() }()
		fn()
	}
	<-finished
	if panicked != nil {
		panic(panicked)
	}
}

// stop ends the thread after the calls already queued have run. The
// adapter calls it once, from Close, after the module is finalized.
func (m *moduleThread) stop() {
	close(m.calls)
	<-m.done
}
