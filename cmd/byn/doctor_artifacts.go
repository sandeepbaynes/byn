package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/privsep"
)

// artifactScanLimit caps how many entries the check walks. Finding one stuck
// file is enough to report the problem, and a project tree can be enormous —
// a health check that takes ten seconds on node_modules is one people stop
// running.
const artifactScanLimit = 20000

// checkStuckArtifacts reports files in the current project that the exec user
// owns and the caller cannot delete.
//
// This is the failure that used to surface as an EACCES from a build tool long
// after byn was involved, with nothing pointing back at byn. Naming it here,
// with the command that fixes it, is the difference between a confusing
// afternoon and a ten-second repair.
func checkStuckArtifacts(env healEnv, cwd string) (healCheck, bool) {
	c := healCheck{Name: "build artifacts writable"}
	if !env.provisioned() {
		return c, false // nothing runs as another user here
	}
	state, err := privsep.LookupState()
	if err != nil || !state.Provisioned {
		return c, false
	}
	execUID := state.ExecUID
	me := os.Getuid()
	if execUID == me {
		return c, false
	}

	var stuck string
	var count, scanned int
	_ = filepath.WalkDir(cwd, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if scanned++; scanned > artifactScanLimit {
			return filepath.SkipAll
		}
		fi, serr := d.Info()
		if serr != nil {
			return nil
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != execUID {
			return nil
		}
		// Owned by the exec user. Only a directory the caller cannot write
		// actually blocks deletion, so report those.
		if d.IsDir() && syscall.Access(path, 2 /* W_OK */) != nil {
			count++
			if stuck == "" {
				if rel, rerr := filepath.Rel(cwd, path); rerr == nil {
					stuck = rel
				} else {
					stuck = path
				}
			}
		}
		return nil
	})

	if count == 0 {
		c.OK = true
		return c, true
	}
	c.Detail = fmt.Sprintf("%d director(ies) here belong to %s and you cannot delete their contents (e.g. %s)",
		count, privsep.ExecUser, stuck)
	c.Fix = "byn repair"
	return c, true
}

// checkHelperFresh reports when the privsep helper on disk is older than the
// byn binary driving it.
//
// The helper that runs lives in libexec with file capabilities and is placed
// there by `byn setup`; installing byn alone leaves it untouched. The two share
// the exec-token protocol, so drift shows up as a helper that does not
// understand something byn has started sending — an error about a flag, from a
// binary nobody remembers installing. Comparing mtimes catches it without
// needing a version handshake.
func checkHelperFresh(env healEnv) (healCheck, bool) {
	c := healCheck{Name: "privsep helper up to date"}
	if !env.provisioned() {
		return c, false
	}
	helper := env.helperPath
	hi, herr := os.Stat(helper)
	if herr != nil {
		return c, false // not installed here; provisioning checks cover that
	}
	self, serr := os.Executable()
	if serr != nil {
		return c, false
	}
	si, serr := os.Stat(self)
	if serr != nil {
		return c, false
	}
	// A day's grace: the two are installed seconds apart normally, and a
	// warning that fires on clock skew is one people learn to ignore.
	if hi.ModTime().Add(24 * time.Hour).After(si.ModTime()) {
		c.OK = true
		return c, true
	}
	c.Detail = fmt.Sprintf("%s is older than byn (%s vs %s) and they share the exec protocol",
		helper, hi.ModTime().Format("2006-01-02"), si.ModTime().Format("2006-01-02"))
	c.Fix = "sudo byn setup"
	return c, true
}

// checkInjectableNames reports whether the .byn in scope will actually receive
// the variables it allowlists.
//
// The only sanctioned probe was an exact-match `byn list NAME`, one call per
// name, which makes "will this service start with what it needs?" tedious
// enough to skip — and skipping it is how a missing value becomes a crash
// halfway through a test run instead of a message before launch.
//
// It reports names, never values, so it stays safe to run anywhere.
func checkInjectableNames() (healCheck, bool) {
	c := healCheck{Name: "declared variables have values"}
	cwd, err := os.Getwd()
	if err != nil {
		return c, false
	}
	bynPath := filepath.Join(cwd, ".byn")
	body, rerr := os.ReadFile(bynPath) // #nosec G304 -- the .byn in the caller's own directory
	if rerr != nil {
		return c, false // no .byn here; nothing is declared
	}
	f, perr := bynfile.Parse(body)
	if perr != nil {
		return c, false // malformed: the trust path reports that far better
	}
	declared := []string(f.Exec.Env)
	// An unattended value that matches NO allowlist is the more suspicious one,
	// not the less: nothing legitimate creates a value the project never asks
	// for. The declared-vs-vault comparison below cannot see those at all, so
	// they are reported first and regardless of what the .byn declares.
	if c, ok := checkStrayUnattended(f, bynPath); ok {
		return c, true
	}
	if len(declared) == 0 || f.AllowsAll() {
		return c, false // nothing named to check against
	}
	// Names the author has said the program can run without.
	optional := make(map[string]struct{}, len(f.Exec.Optional))
	for _, n := range f.Exec.Optional {
		optional[n] = struct{}{}
	}

	dir, derr := defaultDir()
	if derr != nil {
		return c, false
	}
	var resp ipc.ListResp
	if cerr := newClient(dir, f.Scope.Vault).Call(ipc.OpList, ipc.ListReq{
		Scope: ipc.Scope{Vault: f.Scope.Vault, Project: f.Scope.Project, Env: f.Scope.Env},
	}, &resp); cerr != nil {
		return c, false // locked or unreachable: not this check's story to tell
	}
	have := make(map[string]struct{}, len(resp.Secrets))
	for _, e := range resp.Secrets {
		have[e.Name] = struct{}{}
	}
	var missing []string
	for _, n := range declared {
		if _, ok := optional[n]; ok {
			continue
		}
		if _, ok := have[n]; !ok {
			missing = append(missing, n)
		}
	}
	// Values that appeared with nobody behind the call. Worth saying even when
	// nothing is missing: byn cannot tell one an agent invented from one a
	// person provisioned, and for a name where a wrong-but-present value does
	// silent damage, "it has a value" is not the reassurance it looks like.
	var unattended []string
	for _, e := range resp.Secrets {
		if e.Unattended {
			unattended = append(unattended, e.Name)
		}
	}
	// A name the .byn now denies to unattended callers, whose value was stored
	// by one before that deny list existed. It cannot happen going forward, and
	// nothing else would ever mention it — but it is exactly the cleanup an
	// owner has to do after adopting a deny list, and only byn knows about it.
	var deniedButInvented []string
	for _, n := range unattended {
		if pattern, denied := matchesDeny(f.Exec.AgentPutDeny, n); denied {
			deniedButInvented = append(deniedButInvented, n+" (denied by "+pattern+")")
		}
	}
	if len(deniedButInvented) > 0 {
		c.Warn = true
		c.Detail = fmt.Sprintf("%s denies these to unattended callers but already has a value one stored: %s",
			filepath.Base(bynPath), strings.Join(deniedButInvented, ", "))
		c.Fix = "re-set them yourself: echo -n VALUE | byn put NAME"
		return c, true
	}
	if len(missing) == 0 {
		c.OK = true
		c.Detail = fmt.Sprintf("all %d declared in %s", len(declared), filepath.Base(bynPath))
		if len(unattended) > 0 {
			c.OK = false
			c.Warn = true
			c.Detail += fmt.Sprintf("; %d stored with no password behind the call: %s",
				len(unattended), strings.Join(unattended, ", "))
			c.Fix = "check these are the values you meant: byn audit tail --json | grep put.unattended"
		}
		return c, true
	}
	// A warning, not a failure. byn cannot tell a credential someone forgot from
	// one the program treats as optional, and reporting the second as broken
	// left doctor permanently red on healthy checkouts — at which point nobody
	// reads it and the first kind hides in the noise. Say it plainly and let the
	// author silence the ones they mean with [exec] optional.
	c.Warn = true
	c.Detail = fmt.Sprintf("%s declares %s with no value in the vault",
		filepath.Base(bynPath), strings.Join(missing, ", "))
	c.Fix = "echo -n VALUE | byn put " + missing[0] +
		"   (or list it in [exec] optional if the program runs without it)"
	return c, true
}

// matchesDeny reports whether name is covered by any [exec] agent_put_deny
// entry, and by which one. Entries are shell-style globs; a literal name is a
// glob with no metacharacters, so one path serves both. Mirrors the daemon's
// rule — a doctor that disagreed with the gate would send people chasing
// nothing, or worse, reassure them about a name byn does not actually protect.
func matchesDeny(patterns []string, name string) (string, bool) {
	for _, p := range patterns {
		if p == name {
			return p, true
		}
		if ok, err := path.Match(p, name); err == nil && ok {
			return p, true
		}
	}
	return "", false
}

// checkStrayUnattended reports values stored with no credential behind the call
// that the .byn does not declare — an agent invented them and nothing will ever
// inject them, so nobody would otherwise look.
func checkStrayUnattended(f bynfile.File, bynPath string) (healCheck, bool) {
	c := healCheck{Name: "declared variables have values"}
	dir, derr := defaultDir()
	if derr != nil {
		return c, false
	}
	var resp ipc.ListResp
	if cerr := newClient(dir, f.Scope.Vault).Call(ipc.OpList, ipc.ListReq{
		Scope: ipc.Scope{Vault: f.Scope.Vault, Project: f.Scope.Project, Env: f.Scope.Env},
	}, &resp); cerr != nil {
		return c, false
	}
	declared := make(map[string]struct{}, len(f.Exec.Env))
	for _, n := range []string(f.Exec.Env) {
		declared[n] = struct{}{}
	}
	var stray []string
	for _, e := range resp.Secrets {
		if !e.Unattended {
			continue
		}
		if _, ok := declared[e.Name]; ok {
			continue // covered by the declared-vs-vault report
		}
		stray = append(stray, e.Name)
	}
	if len(stray) == 0 {
		return c, false
	}
	c.Warn = true
	c.Detail = fmt.Sprintf("%d value(s) stored with no password behind the call that %s does not declare: %s",
		len(stray), filepath.Base(bynPath), strings.Join(stray, ", "))
	// Actionable by whoever is reading, including an agent: nothing declares
	// these, which is the condition under which byn lets the caller that stored
	// a value remove it. A declared name would need the owner.
	c.Fix = "nothing injects them; remove one with: byn delete " + stray[0]
	return c, true
}
