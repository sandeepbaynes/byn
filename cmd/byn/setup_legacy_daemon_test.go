package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeLegacyDaemon is a scripted per-user daemon: a pidfile naming pid, owned by
// uid, that exits after exitAfter alive-checks once terminated.
type fakeLegacyDaemon struct {
	pid, uid   int
	hasPIDFile bool
	running    bool
	exitAfter  int // alive-checks after SIGTERM before it is gone; -1 = never
	answers    bool

	terminated      []int
	autoStartCalls  int
	autoStartErr    error
	checksSinceTerm int
	clock           time.Time
}

func (f *fakeLegacyDaemon) ops() legacyDaemonOps {
	f.clock = time.Unix(1_000_000, 0)
	return legacyDaemonOps{
		readPID: func(string) (int, bool, error) { return f.pid, f.hasPIDFile, nil },
		alive: func(pid int) bool {
			if pid != f.pid || !f.running {
				return false
			}
			if len(f.terminated) > 0 {
				if f.exitAfter >= 0 && f.checksSinceTerm >= f.exitAfter {
					f.running = false
					return false
				}
				f.checksSinceTerm++
			}
			return true
		},
		ownerUID:  func(int) (int, error) { return f.uid, nil },
		terminate: func(pid int) error { f.terminated = append(f.terminated, pid); return nil },
		socketAnswers: func(string) bool {
			return f.answers || f.running
		},
		removeAutoStart: func(string, int) error { f.autoStartCalls++; return f.autoStartErr },
		now:             func() time.Time { return f.clock },
		sleep:           func(d time.Duration) { f.clock = f.clock.Add(d) },
	}
}

func TestStopLegacyDaemon_NothingRunning(t *testing.T) {
	f := &fakeLegacyDaemon{}
	if err := stopLegacyDaemon("/home/u/.byn", 501, f.ops()); err != nil {
		t.Fatalf("stopLegacyDaemon: %v", err)
	}
	if len(f.terminated) != 0 {
		t.Errorf("signalled %v with nothing running", f.terminated)
	}
	if f.autoStartCalls != 1 {
		t.Errorf("auto-start removal ran %d times, want 1", f.autoStartCalls)
	}
}

func TestStopLegacyDaemon_StopsOwnersDaemonAndWaits(t *testing.T) {
	f := &fakeLegacyDaemon{pid: 4242, uid: 501, hasPIDFile: true, running: true, exitAfter: 3}
	if err := stopLegacyDaemon("/home/u/.byn", 501, f.ops()); err != nil {
		t.Fatalf("stopLegacyDaemon: %v", err)
	}
	if len(f.terminated) != 1 || f.terminated[0] != 4242 {
		t.Errorf("terminated = %v, want [4242]", f.terminated)
	}
	if f.running {
		t.Error("returned before the daemon exited")
	}
}

func TestStopLegacyDaemon_DaemonThatWillNotExitAborts(t *testing.T) {
	f := &fakeLegacyDaemon{pid: 4242, uid: 501, hasPIDFile: true, running: true, exitAfter: -1}
	err := stopLegacyDaemon("/home/u/.byn", 501, f.ops())
	if err == nil || !strings.Contains(err.Error(), "did not exit") {
		t.Fatalf("err = %v, want a did-not-exit error", err)
	}
}

func TestStopLegacyDaemon_RecycledPIDOfAnotherUserIsNotSignalled(t *testing.T) {
	f := &fakeLegacyDaemon{pid: 4242, uid: 0, hasPIDFile: true, running: true}
	// The process is someone else's, so it is not ours to stop; but it answers
	// on no byn socket, so setup may proceed.
	ops := f.ops()
	ops.socketAnswers = func(string) bool { return false }
	if err := stopLegacyDaemon("/home/u/.byn", 501, ops); err != nil {
		t.Fatalf("stopLegacyDaemon: %v", err)
	}
	if len(f.terminated) != 0 {
		t.Errorf("signalled %v, a process the owner does not own", f.terminated)
	}
}

func TestStopLegacyDaemon_SocketAnswersWithoutPIDFileAborts(t *testing.T) {
	f := &fakeLegacyDaemon{answers: true}
	err := stopLegacyDaemon("/home/u/.byn", 501, f.ops())
	if err == nil || !strings.Contains(err.Error(), "still answering") {
		t.Fatalf("err = %v, want a still-answering error", err)
	}
}

func TestStopLegacyDaemon_AutoStartRemovalFailureAborts(t *testing.T) {
	f := &fakeLegacyDaemon{pid: 4242, uid: 501, hasPIDFile: true, running: true, exitAfter: 0,
		autoStartErr: errors.New("read-only file system")}
	err := stopLegacyDaemon("/home/u/.byn", 501, f.ops())
	if err == nil || !strings.Contains(err.Error(), "auto-start") {
		t.Fatalf("err = %v, want an auto-start error", err)
	}
	if len(f.terminated) != 0 {
		t.Error("stopped the daemon although its auto-start service would respawn it")
	}
}
