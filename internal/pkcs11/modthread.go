package pkcs11

import (
	"os"
	"runtime"
)

// moduleThread runs every call into the PKCS#11 module on one OS thread.
// It is an experiment, switched on by HSM_PKI_MODULE_THREAD=1 at adapter
// construction, to measure whether the ProtectToolkit-C emulator's
// C_OpenSession hang under a single caller is a thread-affinity problem:
// Go moves goroutines between OS threads across cgo calls, and a module
// that keeps per-thread state would then see one logical caller arrive
// from many threads. If the hang rate under this thread is zero where the
// unpinned rate is not, the escape hatch is the fix; if it is the same,
// the hypothesis is measured false. Not for production until measured.
type moduleThread struct {
	calls chan func()
	done  chan struct{}
}

func moduleThreadEnabled() bool { return os.Getenv("HSM_PKI_MODULE_THREAD") == "1" }

func newModuleThread() *moduleThread {
	m := &moduleThread{calls: make(chan func()), done: make(chan struct{})}
	go func() {
		// The goroutine, and with it every module call, stays on this
		// thread for the adapter's life.
		runtime.LockOSThread()
		defer close(m.done)
		for fn := range m.calls {
			fn()
		}
	}()
	return m
}

// run executes fn on the module thread and waits for it.
func (m *moduleThread) run(fn func()) {
	finished := make(chan struct{})
	m.calls <- func() {
		defer close(finished)
		fn()
	}
	<-finished
}

// stop ends the thread after the calls already queued have run.
func (m *moduleThread) stop() {
	close(m.calls)
	<-m.done
}
