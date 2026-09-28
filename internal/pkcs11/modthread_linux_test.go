package pkcs11

import (
	"runtime"
	"sync"
	"syscall"
	"testing"
)

// These tests measure the mechanism SerializeOnOneThread turns on, with no
// module loaded: whether the module would have hung is a rate that
// tools/hang-tally.sh measures, but whether every call really arrives on
// one OS thread is a fact about this code, checked here by the kernel's
// thread id. Linux only, because that is where syscall.Gettid exists and
// where every backend here runs.

// callerThreads calls through both lock helpers from several goroutines
// and returns the set of OS threads the calls ran on.
func callerThreads(t *testing.T, a *pkcs11Adapter) map[int]bool {
	t.Helper()
	var mu sync.Mutex
	seen := map[int]bool{}
	record := func() error {
		tid := syscall.Gettid()
		mu.Lock()
		seen[tid] = true
		mu.Unlock()
		runtime.Gosched()
		return nil
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := a.withStateLock(record); err != nil {
					t.Error(err)
				}
				if err := a.withReadLock(record); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	return seen
}

func TestSerializeOnOneThread_EveryCallRunsOnOneOSThread(t *testing.T) {
	a := &pkcs11Adapter{mt: newModuleThread()}
	defer a.mt.stop()

	seen := callerThreads(t, a)
	if len(seen) != 1 {
		t.Fatalf("declared SerializeOnOneThread, but 800 calls ran on %d OS threads: %v", len(seen), seen)
	}
}

// The control: without the declaration, calls run inline, on whatever
// thread the calling goroutine is on. If this ever saw one thread too,
// the test above would prove nothing.
func TestSerializeOnOneThread_UndeclaredCallsRunOnTheCallersThread(t *testing.T) {
	a := &pkcs11Adapter{}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	caller := syscall.Gettid()
	var got int
	if err := a.withStateLock(func() error { got = syscall.Gettid(); return nil }); err != nil {
		t.Fatal(err)
	}
	if got != caller {
		t.Fatalf("undeclared: the call ran on thread %d, the caller is on %d", got, caller)
	}
	if n := len(callerThreads(t, a)); n < 2 {
		t.Skipf("undeclared: 800 calls from eight goroutines happened to share %d OS thread; the contrast is not shown on this run", n)
	}
}

// A panic inside a module call unwinds the caller, as it would inline,
// and the thread keeps serving calls afterwards.
func TestSerializeOnOneThread_APanicReachesTheCaller(t *testing.T) {
	a := &pkcs11Adapter{mt: newModuleThread()}
	defer a.mt.stop()

	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Fatalf("recovered %v in the caller, want the module call's panic", r)
			}
		}()
		_ = a.withStateLock(func() error { panic("boom") })
		t.Fatal("withStateLock returned after its function panicked")
	}()

	ran := false
	if err := a.withStateLock(func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("after a panic: ran=%v err=%v, want the thread still serving calls", ran, err)
	}
}

func TestSerializeOnOneThread_AClosedAdapterRefusesBeforeTheThread(t *testing.T) {
	a := &pkcs11Adapter{mt: newModuleThread(), closed: true}
	defer a.mt.stop()

	called := false
	if err := a.withStateLock(func() error { called = true; return nil }); err != ErrAdapterClosed || called {
		t.Fatalf("closed adapter: err=%v called=%v, want ErrAdapterClosed and no call", err, called)
	}
}
