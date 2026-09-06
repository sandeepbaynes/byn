package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// guideHarness is a machine and a person described for the guide.
type guideHarness struct {
	granted  atomic.Bool
	applies  bool
	opened   atomic.Int32
	restarts atomic.Int32
	openErr  error
	stdout   bytes.Buffer
	stderr   bytes.Buffer
}

func (h *guideHarness) guide(stdin io.Reader, interactive bool, waitFor time.Duration) fdaGuide {
	return fdaGuide{
		probe:       func() (bool, bool) { return h.applies, h.granted.Load() },
		openPane:    func() error { h.opened.Add(1); return h.openErr },
		restart:     func() error { h.restarts.Add(1); return nil },
		binary:      "/usr/local/bin/byn",
		stdin:       stdin,
		stdout:      &h.stdout,
		stderr:      &h.stderr,
		interactive: interactive,
		poll:        5 * time.Millisecond,
		waitFor:     waitFor,
		settle:      50 * time.Millisecond,
	}
}

// blockingStdin answers the question and then says nothing more — a person who
// has not yet pressed Enter.
func blockingStdin(t *testing.T, answer string) io.Reader {
	t.Helper()
	pr, pw := io.Pipe()
	go func() { _, _ = io.WriteString(pw, answer) }()
	t.Cleanup(func() { _ = pw.Close() })
	return pr
}

func TestFDAGuide_NotApplicableSaysNothing(t *testing.T) {
	h := &guideHarness{applies: false}
	assert.Equal(t, fdaNotApplicable, h.guide(strings.NewReader("y\n"), true, time.Second).run())
	assert.Empty(t, h.stdout.String())
	assert.Zero(t, h.opened.Load())
}

func TestFDAGuide_AlreadyGrantedSaysNothing(t *testing.T) {
	h := &guideHarness{applies: true}
	h.granted.Store(true)
	assert.Equal(t, fdaAlreadyGranted, h.guide(strings.NewReader("y\n"), true, time.Second).run())
	assert.Empty(t, h.stdout.String())
}

func TestFDAGuide_NonInteractiveNeverOpensSettings(t *testing.T) {
	h := &guideHarness{applies: true}
	assert.Equal(t, fdaNonInteractive, h.guide(strings.NewReader(""), false, time.Second).run())
	assert.Zero(t, h.opened.Load())
	assert.Zero(t, h.restarts.Load())
}

// The default is no: a bare Enter, or anything that is not a yes, declines —
// and the decline says what will not work, and how to come back.
func TestFDAGuide_DeclinedSaysWhatWillNotWork(t *testing.T) {
	for _, answer := range []string{"\n", "n\n", "no\n", "maybe\n"} {
		h := &guideHarness{applies: true}
		assert.Equal(t, fdaDeclined, h.guide(strings.NewReader(answer), true, time.Second).run(), "answer %q", answer)
		out := h.stdout.String()
		assert.Contains(t, out, "[y/N]")
		assert.Contains(t, out, "~/Documents")
		assert.Contains(t, out, "byn trust")
		assert.Contains(t, out, "doctor --repair")
		assert.Zero(t, h.opened.Load(), "declining must not open System Settings")
		assert.Zero(t, h.restarts.Load())
	}
}

// The switch flips while the guide is watching: no Enter, no restart needed.
func TestFDAGuide_SeesTheSwitchFlipWithoutEnter(t *testing.T) {
	h := &guideHarness{applies: true}
	go func() {
		time.Sleep(20 * time.Millisecond)
		h.granted.Store(true)
	}()
	rc := h.guide(blockingStdin(t, "y\n"), true, 2*time.Second).run()
	assert.Equal(t, fdaGrantedNow, rc)
	assert.Equal(t, int32(1), h.opened.Load())
	assert.Zero(t, h.restarts.Load(), "a grant the running daemon already sees needs no restart")
	out := h.stdout.String()
	assert.Contains(t, out, "/usr/local/bin/byn", "the file to add is named")
	assert.Contains(t, out, "Cmd-Shift-G")
	assert.Contains(t, out, "Touch ID")
	assert.Contains(t, out, "Full Disk Access granted")
}

// Enter is the owner's word that the switch is on; the daemon is restarted
// and asked again, because a daemon started before the grant may not see it.
func TestFDAGuide_EnterRestartsAndVerifies(t *testing.T) {
	h := &guideHarness{applies: true}
	// The grant appears only after a restart — the case a restart exists for.
	guide := h.guide(strings.NewReader("y\n\n"), true, 2*time.Second)
	guide.restart = func() error { h.restarts.Add(1); h.granted.Store(true); return nil }
	assert.Equal(t, fdaGrantedNow, guide.run())
	assert.Equal(t, int32(1), h.restarts.Load())
	assert.Contains(t, h.stdout.String(), "Restarting the daemon")
}

func TestFDAGuide_EnterButStillRefused(t *testing.T) {
	h := &guideHarness{applies: true}
	rc := h.guide(strings.NewReader("y\n\n"), true, 2*time.Second).run()
	assert.Equal(t, fdaStillMissing, rc)
	assert.Equal(t, int32(1), h.restarts.Load())
	out := h.stdout.String()
	assert.Contains(t, out, "still not granted")
	assert.Contains(t, out, "/usr/local/bin/byn", "the likely mistake is a grant to the wrong copy")
	assert.Contains(t, out, "doctor --repair")
}

// Nobody presses Enter and nothing changes: the guide gives up on its own
// rather than holding setup hostage, and does not restart a daemon for nothing.
func TestFDAGuide_TimesOutWithoutRestarting(t *testing.T) {
	h := &guideHarness{applies: true}
	rc := h.guide(blockingStdin(t, "y\n"), true, 60*time.Millisecond).run()
	assert.Equal(t, fdaStillMissing, rc)
	assert.Zero(t, h.restarts.Load())
}

// System Settings failing to open is a warning with the manual path, not the
// end of the flow — the person can still get there themselves.
func TestFDAGuide_OpenFailureStillWaits(t *testing.T) {
	h := &guideHarness{applies: true, openErr: errors.New("open: no session")}
	go func() {
		time.Sleep(20 * time.Millisecond)
		h.granted.Store(true)
	}()
	rc := h.guide(blockingStdin(t, "yes\n"), true, 2*time.Second).run()
	require.Equal(t, fdaGrantedNow, rc)
	assert.Contains(t, h.stderr.String(), "could not open System Settings")
	assert.Contains(t, h.stderr.String(), "Privacy & Security")
}
