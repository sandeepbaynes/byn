package main

// fda_guide.go walks the owner through granting the daemon Full Disk Access.
//
// macOS has no API to request Full Disk Access — no dialog, no prompt, nothing
// an installer or a root process can trigger. The grant is made by a person
// flipping a switch in System Settings, and that switch is what asks for the
// password or fingerprint. So the most byn can do is what a good colleague
// would do standing behind you: ask whether you want it at all, open the exact
// pane, say which file to add, and notice when the switch has been flipped.
//
// Asking first is deliberate. The grant is only needed for projects under
// ~/Documents, ~/Desktop, ~/Downloads or iCloud Drive; someone who keeps their
// code in ~/code needs nothing, and a wizard that insists would be teaching
// people to grant a system-wide permission they have no use for.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/privsep"
)

// fdaPaneURL deep-links System Settings to the Full Disk Access list.
const fdaPaneURL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"

// fdaOutcome is what the guide did, for callers and tests.
type fdaOutcome int

const (
	fdaNotApplicable  fdaOutcome = iota // not macOS with privsep, or the daemon could not be asked
	fdaAlreadyGranted                   // nothing to do
	fdaNonInteractive                   // nobody to ask; printed the manual steps
	fdaDeclined                         // the owner said no
	fdaGrantedNow                       // the switch was flipped while we watched
	fdaStillMissing                     // waited, restarted, still refused
)

// fdaGuide is the flow with every side effect injected, so a test can describe
// a machine and a person rather than depend on the one running it.
type fdaGuide struct {
	// probe asks the DAEMON whether it holds the grant. applies is false where
	// the question is meaningless (not macOS, no privsep) or unanswerable
	// (daemon down): both mean the guide has nothing to offer.
	probe    func() (applies, granted bool)
	openPane func() error
	restart  func() error
	binary   string // the file to add in System Settings
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	// interactive is whether there is a person at stdin to ask.
	interactive bool
	poll        time.Duration // between probes while waiting
	waitFor     time.Duration // how long to wait for the switch
	settle      time.Duration // how long to give a restarted daemon to report the grant
}

// run drives the whole flow and reports what happened.
func (g fdaGuide) run() fdaOutcome {
	applies, granted := g.probe()
	if !applies {
		return fdaNotApplicable
	}
	if granted {
		return fdaAlreadyGranted
	}
	if !g.interactive {
		printMacOSFDANote(g.stdout)
		return fdaNonInteractive
	}
	in := bufio.NewReader(g.stdin)
	_, _ = fmt.Fprintln(g.stdout, "")
	_, _ = fmt.Fprintln(g.stdout, "macOS blocks the daemon (running as "+cyan(privsep.DaemonUser)+
		") from reading .byn files under "+cyan("~/Documents")+", "+cyan("~/Desktop")+", "+
		cyan("~/Downloads")+" and iCloud Drive unless it has "+bold("Full Disk Access")+".")
	_, _ = fmt.Fprintln(g.stdout, "Projects anywhere else (e.g. "+cyan("~/code")+") need nothing.")
	if !g.ask(in) {
		g.printDeclined()
		return fdaDeclined
	}
	g.printSteps()
	if err := g.openPane(); err != nil {
		_, _ = fmt.Fprintf(g.stderr, "warning: could not open System Settings (%v)\n", err)
		_, _ = fmt.Fprintln(g.stderr, "         open it yourself: "+
			cyan("System Settings > Privacy & Security > Full Disk Access"))
	}
	_, _ = fmt.Fprintln(g.stdout, "Waiting for the grant… press "+bold("Enter")+
		" once the switch is on ("+bold("Ctrl-C")+" to stop waiting).")
	if g.wait(in) {
		_, _ = fmt.Fprintln(g.stdout, bold("Full Disk Access granted.")+
			" The daemon can read .byn files anywhere.")
		return fdaGrantedNow
	}
	g.printStillMissing()
	return fdaStillMissing
}

// ask puts the question and reads one line; anything but a leading y is no.
func (g fdaGuide) ask(in *bufio.Reader) bool {
	_, _ = fmt.Fprint(g.stdout, "Grant Full Disk Access to the byn daemon now? [y/N] ")
	line, _ := in.ReadString('\n')
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}

func (g fdaGuide) printDeclined() {
	_, _ = fmt.Fprintln(g.stdout, "Skipped. Until it is granted, "+cyan("byn trust")+" and "+cyan("byn exec")+
		" are refused for projects under ~/Documents, ~/Desktop, ~/Downloads and iCloud Drive.")
	_, _ = fmt.Fprintln(g.stdout, "To grant it later: "+cyan(sudoByn("doctor", "--repair")))
}

func (g fdaGuide) printSteps() {
	_, _ = fmt.Fprintln(g.stdout, "Opening "+cyan("System Settings > Privacy & Security > Full Disk Access")+"…")
	_, _ = fmt.Fprintln(g.stdout, "  1. Turn on the switch next to "+bold("byn")+".")
	_, _ = fmt.Fprintln(g.stdout, "     If byn is not listed: click "+bold("+")+", press "+bold("Cmd-Shift-G")+
		", paste "+cyan(g.binary)+" and choose Open.")
	_, _ = fmt.Fprintln(g.stdout, "  2. Approve with your password or Touch ID.")
}

func (g fdaGuide) printStillMissing() {
	_, _ = fmt.Fprintln(g.stdout, boldYellow("Full Disk Access is still not granted."))
	_, _ = fmt.Fprintln(g.stdout, "  • Check the switch is on for the daemon's binary, "+cyan(g.binary)+
		" — a grant to a different copy of byn does nothing.")
	_, _ = fmt.Fprintln(g.stdout, "  • Then run "+cyan(sudoByn("doctor", "--repair"))+" to try again, or "+
		cyan("byn status")+" to see the state.")
}

// wait watches for the grant until it appears, the owner presses Enter, or
// time runs out.
//
// Two ways to learn the switch was flipped, because it is not certain which
// one works: TCC may let a running process see a new grant on its next open,
// or it may not — the daemon started before the grant existed. So the guide
// polls the daemon as it is, and when the owner says the switch is on it
// restarts the daemon and looks again. Enter is the owner's word; the probe
// after the restart is the check on it.
func (g fdaGuide) wait(in *bufio.Reader) bool {
	enter := make(chan struct{}, 1)
	go func() {
		// A closed stdin (EOF) counts as Enter: there is nothing more to wait
		// for from that side, and the restart-and-probe is still worth doing.
		_, _ = in.ReadString('\n')
		enter <- struct{}{}
	}()
	tick := time.NewTicker(g.poll)
	defer tick.Stop()
	deadline := time.After(g.waitFor)
	for {
		select {
		case <-tick.C:
			if _, granted := g.probe(); granted {
				return true
			}
		case <-enter:
			_, _ = fmt.Fprintln(g.stdout, "Restarting the daemon so it picks up the grant…")
			if err := g.restart(); err != nil {
				_, _ = fmt.Fprintf(g.stderr, "warning: restart failed: %v\n", err)
			}
			return g.settleProbe()
		case <-deadline:
			return false
		}
	}
}

// settleProbe gives a restarted daemon up to settle to come back and answer.
func (g fdaGuide) settleProbe() bool {
	deadline := time.Now().Add(g.settle)
	for {
		if applies, granted := g.probe(); applies && granted {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(g.poll)
	}
}

// fdaGuideFn is the production guide, replaceable in tests so `byn setup` and
// `byn doctor --repair` tests do not spawn sudo or System Settings.
var fdaGuideFn = runFDAGuide

// runFDAGuide wires the guide to the machine. It runs as root — that is what
// setup and repair are — and the two things that must NOT happen as root are
// done as the invoking human instead:
//
//   - the probe: the daemon refuses a root peer, and root has no more standing
//     with TCC than anyone (a root probe of the TCC database would report the
//     Terminal's grant, not the daemon's); so it runs `byn status --json` as
//     SUDO_USER and reads fda_granted, which the daemon measured of itself;
//   - opening System Settings, which belongs to the person's login session.
//
// The restart is root's job and stays here.
func runFDAGuide(stdin io.Reader, stdout, stderr io.Writer) fdaOutcome {
	if runtime.GOOS != "darwin" {
		return fdaNotApplicable
	}
	owner := os.Getenv("SUDO_USER")
	self, err := os.Executable()
	if owner == "" || err != nil {
		// Real root with nobody behind it, or no idea what to re-run: say the
		// manual steps and stop. Not an error — setup as real root is allowed.
		printMacOSFDANote(stdout)
		return fdaNonInteractive
	}
	binary, berr := privsep.InstalledServiceExecPath()
	if berr != nil {
		binary = self
	}
	return fdaGuide{
		probe:       func() (bool, bool) { return probeFDAAs(owner, self) },
		openPane:    func() error { return exec.Command("sudo", "-u", owner, "open", fdaPaneURL).Run() }, // #nosec G204 -- fixed URL, user from sudo
		restart:     func() error { return privsep.RestartService(privilegedRunner()) },
		binary:      binary,
		stdin:       stdin,
		stdout:      stdout,
		stderr:      stderr,
		interactive: stdinIsTTY(),
		poll:        time.Second,
		waitFor:     5 * time.Minute,
		settle:      15 * time.Second,
	}.run()
}

// probeFDAAs asks the daemon, as the owner, whether it holds Full Disk Access.
func probeFDAAs(owner, self string) (applies, granted bool) {
	out, err := exec.Command("sudo", "-u", owner, self, "status", "--json").Output() // #nosec G204 -- own binary, user from sudo
	if err != nil {
		return false, false
	}
	var resp ipc.StatusResp
	if json.Unmarshal(out, &resp) != nil || resp.FDAGranted == nil {
		return false, false
	}
	return true, *resp.FDAGranted
}
