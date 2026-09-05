//go:build darwin

package main

import "testing"

// realPSOutput is a verbatim capture from `ps -axo pid=,ppid=,uid=,command=` on
// a provisioned Mac running two `byn exec` jobs, trimmed to the interesting
// rows plus enough noise to prove the filter discriminates.
//
// It is real output rather than an invented shape on purpose: the bug this file
// fixes was a platform path that compiled and did nothing, and the only thing
// that catches that class is asserting against what the platform actually emits.
const realPSOutput = `27853     1   501 byn exec -- ./server.sh
27855 27853   451 bash /Users/me/proj/server.sh
53860 53858   501 ../bin/byn exec -- ./server.sh
53862 53860   451 bash /Users/me/proj/server.sh
  501     1     0 /sbin/launchd
 1234     1   501 /Applications/Safari.app/Contents/MacOS/Safari
`

func TestParsePSRows_RealOutput(t *testing.T) {
	rows := parsePSRows(realPSOutput)
	if len(rows) != 6 {
		t.Fatalf("want 6 rows, got %d: %+v", len(rows), rows)
	}
	first := rows[0]
	if first.pid != 27853 || first.ppid != 1 || first.uid != 501 {
		t.Errorf("row 0 = %+v, want pid 27853 ppid 1 uid 501", first)
	}
	if first.command != "byn exec -- ./server.sh" {
		t.Errorf("row 0 command = %q", first.command)
	}
	// launchd's row has uid 0 and a leading-space pid: the columns are
	// right-aligned, and reading them positionally would mis-parse it.
	if rows[4].pid != 501 || rows[4].uid != 0 {
		t.Errorf("row 4 = %+v, want pid 501 uid 0 (right-aligned columns)", rows[4])
	}
}

func TestParsePSRows_CommandKeepsInternalSpacing(t *testing.T) {
	// A path with a space in it is one argument. Rebuilding the command by
	// joining Fields would silently collapse it to one space and produce a path
	// that does not exist.
	rows := parsePSRows("42 1 501 bash /Users/me/my  project/run.sh\n")
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if want := "bash /Users/me/my  project/run.sh"; rows[0].command != want {
		t.Errorf("command = %q, want %q", rows[0].command, want)
	}
}

func TestParsePSRows_SkipsGarbage(t *testing.T) {
	for _, in := range []string{"", "\n\n", "not a row", "x 1 501 cmd", "1 y 501 cmd", "1 2 z cmd", "1 2 3"} {
		if got := parsePSRows(in); len(got) != 0 {
			t.Errorf("parsePSRows(%q) = %+v, want none", in, got)
		}
	}
}

func TestIsBynExecWrapper(t *testing.T) {
	cases := []struct {
		command string
		want    string
		ok      bool
	}{
		{"byn exec -- ./server.sh", "./server.sh", true},
		{"/usr/local/bin/byn exec -- pnpm start", "pnpm start", true},
		// A dev build run from the tree must still be recognised, or ps lists
		// nothing for exactly the person most likely to be debugging it.
		{"../bin/byn exec -- ./server.sh", "./server.sh", true},
		{"byn exec --vault w -- npm i", "npm i", true},
		{"byn exec myalias", "myalias", true},
		// Not us.
		{"bash /Users/me/proj/server.sh", "", false},
		{"byn status", "", false},
		{"/sbin/launchd", "", false},
		{"mybyn exec -- x", "", false}, // suffix match would wrongly claim this
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := isBynExecWrapper(tc.command)
		if ok != tc.ok || got != tc.want {
			t.Errorf("isBynExecWrapper(%q) = (%q,%v), want (%q,%v)", tc.command, got, ok, tc.want, tc.ok)
		}
	}
}

func TestClassifyExecProcs_PrivsepMachine(t *testing.T) {
	// Provisioned: one row per job, which is the wrapper. The exec-user child
	// under it is the same job seen from the inside, and killing the wrapper
	// takes the group — so a second row would be a second thing to reason about
	// for one running command. Linux lists it the same way.
	got := classifyExecProcs(parsePSRows(realPSOutput), 451, nil)
	if len(got) != 2 {
		t.Fatalf("want 2 byn procs (one per job), got %d: %+v", len(got), got)
	}
	byPID := map[int]string{}
	for _, p := range got {
		byPID[p.pid] = p.command
	}
	for _, pid := range []int{27853, 53860} {
		if byPID[pid] != "./server.sh" {
			t.Errorf("wrapper %d command = %q, want the summarized %q", pid, byPID[pid], "./server.sh")
		}
	}
	if _, listed := byPID[27855]; listed {
		t.Error("the exec-user child under a listed wrapper got its own row")
	}
	if _, listed := byPID[1234]; listed {
		t.Error("Safari was listed as a byn exec process")
	}
	if _, listed := byPID[501]; listed {
		t.Error("launchd was listed as a byn exec process")
	}
}

func TestClassifyExecProcs_UnprovisionedUsesTheEnvMarker(t *testing.T) {
	// No service account (execUID -1), so rule 2 is off. The syscall.Exec'd child
	// is identified only by carrying BYN_EXEC_PID equal to its own pid.
	rows := parsePSRows("900 1 501 node server.js\n901 900 501 node worker.js\n")
	got := classifyExecProcs(rows, -1, map[int]bool{900: true})
	if len(got) != 1 || got[0].pid != 900 {
		t.Fatalf("want only pid 900, got %+v", got)
	}
	if got[0].command != "node server.js" {
		t.Errorf("command = %q", got[0].command)
	}
}

func TestClassifyExecProcs_NoServiceAccountDoesNotMatchUIDMinusOne(t *testing.T) {
	// Guarding the sentinel: -1 must disable the uid rule, not become a uid to
	// compare against. A row can never have uid -1, but the check is cheap and
	// the failure would be silent over-listing.
	rows := parsePSRows("700 1 501 bash /x.sh\n")
	if got := classifyExecProcs(rows, -1, nil); len(got) != 0 {
		t.Errorf("want nothing listed, got %+v", got)
	}
}

func TestClassifyExecProcs_ListsEachPIDOnce(t *testing.T) {
	// A wrapper running AS the service user would satisfy rules 1 and 2 both.
	rows := parsePSRows("55 1 451 byn exec -- ./x.sh\n")
	got := classifyExecProcs(rows, 451, map[int]bool{55: true})
	if len(got) != 1 {
		t.Fatalf("want one entry, got %d: %+v", len(got), got)
	}
	if got[0].command != "./x.sh" {
		t.Errorf("the wrapper rule should win and summarize; got %q", got[0].command)
	}
}

func TestSummarizeExecCommand(t *testing.T) {
	cases := map[string]string{}
	cases[""] = ""
	for _, tc := range []struct{ in, want string }{
		{"-- pnpm start", "pnpm start"},
		{"--vault w -- npm i", "npm i"},
		{"myalias", "myalias"},
		{"--json", "--json"},
	} {
		var args []string
		if tc.in != "" {
			args = splitFields(tc.in)
		}
		if got := summarizeExecCommand(args); got != tc.want {
			t.Errorf("summarizeExecCommand(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	_ = cases
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestClassifyExecProcs_ExcludesGrandchildrenOfAListedWrapper(t *testing.T) {
	// server.sh loops over `sleep 1`, so each iteration spawns a fresh process
	// as the exec user. Listing them put a row per iteration in `byn ps` and the
	// output changed every second. The wrapper is the job; its subtree is not.
	rows := parsePSRows(`100   1 501 byn exec -- ./server.sh
101 100 451 bash /Users/me/proj/server.sh
102 101 451 sleep 1
`)
	got := classifyExecProcs(rows, 451, nil)
	if len(got) != 1 || got[0].pid != 100 {
		t.Fatalf("want only the wrapper (100), got %+v", got)
	}
}

func TestClassifyExecProcs_ListsAnOrphanedChild(t *testing.T) {
	// The mirror case, and the one that matters for `byn kill`: the wrapper is
	// gone (reparented to launchd) and the child is still holding secrets. It has
	// no wrapper to be a descendant of, so it must appear.
	rows := parsePSRows(`201   1 451 bash /Users/me/proj/server.sh
202 201 451 sleep 1
`)
	got := classifyExecProcs(rows, 451, nil)
	if len(got) != 1 || got[0].pid != 201 {
		t.Fatalf("want the orphan (201) and not its child, got %+v", got)
	}
}

func TestTopmostExecProc_OnlyTheHeadOfAJob(t *testing.T) {
	wrappers := map[int]bool{100: true}
	uidOf := map[int]int{100: 501, 101: 451, 201: 451, 1: 0}
	cases := []struct {
		name string
		row  psRow
		want bool
	}{
		{"child of a wrapper", psRow{pid: 101, ppid: 100, uid: 451}, false},
		{"child of an exec-user process", psRow{pid: 102, ppid: 101, uid: 451}, false},
		{"orphan reparented to launchd", psRow{pid: 201, ppid: 1, uid: 451}, true},
		{"parent not in the table at all", psRow{pid: 300, ppid: 9999, uid: 451}, true},
	}
	for _, tc := range cases {
		if got := topmostExecProc(tc.row, wrappers, uidOf, 451); got != tc.want {
			t.Errorf("%s: topmostExecProc = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestClassifyExecProcs_ExcludesSystemDaemons(t *testing.T) {
	// launchd starts distnoted and lsd for ANY account, the exec service user
	// included. Rule 2 identifies a job by uid alone, so without a filter these
	// appear in the listing used to hunt for a stuck dev server — and would be
	// signalled by `byn kill --all`.
	rows := []psRow{
		{pid: 100, ppid: 1, uid: 451, command: "/usr/sbin/distnoted agent"},
		{pid: 101, ppid: 1, uid: 451, command: "/usr/libexec/lsd"},
		{pid: 102, ppid: 1, uid: 451, command: "/System/Library/Foo/bar"},
		{pid: 103, ppid: 1, uid: 451, command: "node /opt/homebrew/bin/pnpm dev"},
	}
	got := classifyExecProcs(rows, 451, nil)
	if len(got) != 1 {
		t.Fatalf("got %d rows, want only the real orphan: %+v", len(got), got)
	}
	if got[0].pid != 103 {
		t.Errorf("kept pid %d, want the pnpm orphan 103", got[0].pid)
	}
}

func TestSystemDaemonCommand(t *testing.T) {
	for _, c := range []string{"/usr/sbin/distnoted agent", "/usr/libexec/lsd", "/System/Library/X"} {
		if !systemDaemonCommand(c) {
			t.Errorf("%q should be filtered", c)
		}
	}
	// A real child must never be filtered, however it was launched.
	for _, c := range []string{"node /opt/homebrew/bin/pnpm dev", "npm start", "/Users/me/bin/tool"} {
		if systemDaemonCommand(c) {
			t.Errorf("%q must not be filtered", c)
		}
	}
}
