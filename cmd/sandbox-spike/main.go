//go:build linux

// sandbox-spike proves the byn v2 exec-isolation mechanism end to end:
// a rootless user namespace whose target process runs at a subuid kuid
// (unreadable /proc from the real UID) while files it creates are swept
// back to the real user by the ns-root shim (dual mapping), all without
// root or a setuid helper.
//
// Modes (selected by argv[1]):
//
//	probe   — live-probe each layer and print the achievable tier
//	verify  — run the full acceptance: spawn sandbox, attack it from
//	          outside, check file ownership after the sweep
//	shim    — internal: pid 1 inside the namespace (do not run by hand)
//
// Inner uid layout:
//
//	0    -> subuid[0]   shim (ns root: mounts /proc, sweeps files)
//	1000 -> real uid    ownership alias: chown target here => user-owned on disk
//	2000 -> subuid[1]   the exec target (protected from same-UID readers)
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	innerShim   = 0
	innerOwner  = 1000
	innerTarget = 2000
)

// Capability numbers (linux/capability.h) carried as ambient caps.
const (
	capChown       = 0
	capDACOverride = 1
	capFowner      = 3
	capSetgid      = 6
	capSetuid      = 7
	capSysAdmin    = 21
)

type subidRange struct{ base, count int }

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "spike: "+format+"\n", a...)
	os.Exit(1)
}

func lookupSubid(file, user string) (subidRange, error) {
	f, err := os.Open(file)
	if err != nil {
		return subidRange{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), ":")
		if len(parts) == 3 && parts[0] == user {
			base, err1 := strconv.Atoi(parts[1])
			count, err2 := strconv.Atoi(parts[2])
			if err1 == nil && err2 == nil {
				return subidRange{base, count}, nil
			}
		}
	}
	return subidRange{}, fmt.Errorf("no %s entry for %s", file, user)
}

func username() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	out, err := exec.Command("id", "-un").Output()
	if err != nil {
		fail("cannot resolve username: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// writeMaps drives newuidmap/newgidmap for the dual mapping.
func writeMaps(pid int, uidr, gidr subidRange, realUID, realGID int) error {
	uidArgs := []string{strconv.Itoa(pid),
		strconv.Itoa(innerShim), strconv.Itoa(uidr.base), "1",
		strconv.Itoa(innerOwner), strconv.Itoa(realUID), "1",
		strconv.Itoa(innerTarget), strconv.Itoa(uidr.base + 1), "1",
	}
	gidArgs := []string{strconv.Itoa(pid),
		strconv.Itoa(innerShim), strconv.Itoa(gidr.base), "1",
		strconv.Itoa(innerOwner), strconv.Itoa(realGID), "1",
		strconv.Itoa(innerTarget), strconv.Itoa(gidr.base + 1), "1",
	}
	if out, err := exec.Command("newuidmap", uidArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("newuidmap: %v: %s", err, out)
	}
	if out, err := exec.Command("newgidmap", gidArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("newgidmap: %v: %s", err, out)
	}
	return nil
}

// spawnSandbox starts the shim in fresh user+pid+mount namespaces, writes the
// dual mapping, and returns the shim process plus a pipe carrying its reports.
func spawnSandbox(dir string, secretEnv []string, argv []string) (*exec.Cmd, *os.File, error) {
	reportR, reportW, err := os.Pipe() // shim -> parent: "target <pid>", "swept", ...
	if err != nil {
		return nil, nil, err
	}
	goR, goW, err := os.Pipe() // parent -> shim: "go" once maps are written
	if err != nil {
		return nil, nil, err
	}
	envR, envW, err := os.Pipe() // secrets travel over an fd, never argv/files
	if err != nil {
		return nil, nil, err
	}

	cmd := exec.Command("/proc/self/exe", append([]string{"shim", dir}, argv...)...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// fd 3=report, 4=go-signal, 5=env
	cmd.ExtraFiles = []*os.File{reportW, goR, envR}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		// Capabilities granted at namespace creation are wiped by the shim's
		// own execve (inner uid is not 0 yet, and no file caps exist rootless).
		// Ambient caps are the only rootless way to carry them through, and
		// they are confined to this user namespace.
		AmbientCaps: []uintptr{
			capChown, capDACOverride, capFowner, capSetgid, capSetuid, capSysAdmin,
		},
		// The shim runs at a subuid kuid, so the real user cannot signal it
		// directly (it holds the secrets — that is the point). Teardown
		// therefore cascades: user kills the wrapper -> pdeathsig kills the
		// shim -> pdeathsig kills the target.
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("clone: %w", err)
	}
	reportW.Close()
	goR.Close()
	envR.Close()

	user := username()
	uidr, err := lookupSubid("/etc/subuid", user)
	if err != nil {
		return nil, nil, err
	}
	gidr, err := lookupSubid("/etc/subgid", user)
	if err != nil {
		return nil, nil, err
	}
	if err := writeMaps(cmd.Process.Pid, uidr, gidr, os.Getuid(), os.Getgid()); err != nil {
		cmd.Process.Kill()
		return nil, nil, err
	}

	for _, kv := range secretEnv {
		fmt.Fprintln(envW, kv)
	}
	envW.Close()
	fmt.Fprintln(goW, "go")
	goW.Close()
	return cmd, reportR, nil
}

// shimMain is pid 1 inside the namespaces.
func shimMain() {
	dir := os.Args[2]
	argv := os.Args[3:]
	report := os.NewFile(3, "report")
	goSig := os.NewFile(4, "go")
	envPipe := os.NewFile(5, "env")

	// Wait until the parent has written uid_map/gid_map.
	if _, err := bufio.NewReader(goSig).ReadString('\n'); err != nil {
		fail("shim: waiting for go signal: %v", err)
	}

	var secretEnv []string
	sc := bufio.NewScanner(envPipe)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			secretEnv = append(secretEnv, line)
		}
	}

	if err := syscall.Setgroups([]int{innerShim}); err != nil {
		fail("shim: setgroups: %v", err)
	}
	if err := syscall.Setresgid(innerShim, innerShim, innerShim); err != nil {
		fail("shim: setresgid: %v", err)
	}
	if err := syscall.Setresuid(innerShim, innerShim, innerShim); err != nil {
		fail("shim: setresuid: %v", err)
	}

	// A credential change clears the parent-death signal, so it must be set
	// again here — after setresuid, not via SysProcAttr. The shim is pid 1 of
	// the new PID namespace, so its death makes the kernel SIGKILL everything
	// inside; that is what tears the target down, not per-process pdeathsig
	// (which the target's own uid change would clear too).
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL,
		syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0); errno != 0 {
		fail("shim: set pdeathsig: %v", errno)
	}
	// Note: getppid() is 0 here — the wrapper lives outside this PID namespace,
	// so it cannot be used to detect a parent that died before the signal was
	// armed. Production closes that race with a lifeline fd the wrapper holds
	// open (EOF on its death), rather than a getppid check.

	// Private mount view + fresh /proc so the outside sees this pidns's
	// processes only through their (unreadable) kuids.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fail("shim: make / private: %v", err)
	}
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		fail("shim: mount /proc: %v", err)
	}

	// The target must be able to write the project dir. In the real design an
	// idmapped mount handles this; the rootless spike grants group write on
	// the workspace to the target's inner gid instead (chown to alias later).
	if err := os.Chown(dir, innerTarget, innerTarget); err != nil {
		fail("shim: chown workspace: %v", err)
	}

	target := exec.Command(argv[0], argv[1:]...)
	target.Dir = dir
	target.Stdout, target.Stderr = os.Stdout, os.Stderr
	target.Env = secretEnv
	target.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    innerTarget,
			Gid:    innerTarget,
			Groups: []uint32{innerTarget},
		},
		Pdeathsig: syscall.SIGKILL,
	}
	if err := target.Start(); err != nil {
		fail("shim: start target: %v", err)
	}
	fmt.Fprintf(report, "target %d\n", target.Process.Pid)

	targetErr := target.Wait()

	// Chown-sweep: everything the target created becomes owner-alias uid,
	// i.e. the real user on disk. (v2 journals this; the spike proves the
	// permission model.)
	sweepErr := filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var st syscall.Stat_t
		if err := syscall.Lstat(path, &st); err != nil {
			return err
		}
		if int(st.Uid) == innerTarget {
			if err := os.Lchown(path, innerOwner, innerOwner); err != nil {
				return err
			}
		}
		return nil
	})
	if sweepErr != nil {
		fmt.Fprintf(report, "sweep-error %v\n", sweepErr)
	} else {
		fmt.Fprintln(report, "swept")
	}
	if targetErr != nil {
		os.Exit(1)
	}
}

// findChildOf returns the host pid of the single child of ppid.
func findChildOf(ppid int) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	var found []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue // raced with exit
		}
		// Fields after the ")"-terminated comm: state, ppid, ...
		i := strings.LastIndex(string(stat), ") ")
		if i < 0 {
			continue
		}
		fields := strings.Fields(string(stat)[i+2:])
		if len(fields) < 2 {
			continue
		}
		if parent, _ := strconv.Atoi(fields[1]); parent == ppid {
			found = append(found, pid)
		}
	}
	switch len(found) {
	case 0:
		return 0, errors.New("no child found (target already exited?)")
	case 1:
		return found[0], nil
	default:
		return 0, fmt.Errorf("ambiguous: %v", found)
	}
}

func procUID(pid int) int {
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d", pid), &st); err != nil {
		return -1
	}
	return int(st.Uid)
}

func sanitize(b []byte) string {
	return strings.ReplaceAll(strings.TrimSpace(string(b)), "\x00", " ")
}

func probeMain() {
	user := username()
	ok := true

	if r, err := lookupSubid("/etc/subuid", user); err == nil {
		fmt.Printf("PASS subuid range %d:%d (source: /etc/subuid)\n", r.base, r.count)
	} else {
		fmt.Printf("FAIL subuid: %v (LDAP/AD hosts need libsubid — v2 requirement)\n", err)
		ok = false
	}

	for _, bin := range []string{"newuidmap", "newgidmap"} {
		path, err := exec.LookPath(bin)
		if err != nil {
			fmt.Printf("FAIL %s: not found\n", bin)
			ok = false
			continue
		}
		// Live probe happens implicitly in verify; here report the privilege bits.
		out, _ := exec.Command("getcap", path).Output()
		var st syscall.Stat_t
		syscall.Stat(path, &st)
		setuid := st.Mode&syscall.S_ISUID != 0
		fmt.Printf("PASS %s (setuid=%v caps=%q)\n", bin, setuid, strings.TrimSpace(string(out)))
	}

	// Landlock ABI via landlock_create_ruleset(NULL, 0, VERSION).
	abi, _, errno := syscall.Syscall(444, 0, 0, 1)
	if errno == 0 {
		fmt.Printf("PASS landlock ABI %d\n", abi)
	} else {
		fmt.Printf("WARN landlock unavailable (%v) — tier keeps userns isolation, loses fs scoping\n", errno)
	}

	// Idmapped-mount creation needs CAP_SYS_ADMIN over the superblock: expected
	// to fail rootless. The check that matters here is per-filesystem support,
	// which the privileged broker probes for real in v2.
	fmt.Println("INFO idmapped-mount probe requires the privileged broker (package install) — rootless tier uses dual-map + sweep")

	if !ok {
		os.Exit(1)
	}
}

// controlCheck proves the attack used by verifyMain actually works against an
// unprotected process — otherwise "environ unreadable" could pass for trivial
// reasons (wrong pid, process already exited) and prove nothing.
func controlCheck(secret string) {
	c := exec.Command("/bin/sh", "-c", "sleep 2; :")
	c.Env = []string{secret}
	if err := c.Start(); err != nil {
		fail("control: start: %v", err)
	}
	defer func() { c.Process.Kill(); c.Wait() }()
	time.Sleep(200 * time.Millisecond)
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", c.Process.Pid))
	if err != nil {
		fail("control: environ of an unsandboxed same-UID process should be readable, got %v", err)
	}
	if !strings.Contains(string(b), secret) {
		fail("control: secret not visible in unsandboxed environ")
	}
	fmt.Println("PASS control: unsandboxed process leaks its secret to any same-UID reader")
}

func verifyMain() {
	dir, err := os.MkdirTemp("", "spike-ws-*")
	if err != nil {
		fail("mkdtemp: %v", err)
	}
	defer os.RemoveAll(dir)

	const secret = "SPIKE_SECRET=byn-spike-3f9a1c"
	controlCheck(secret)
	// Trailing ":" keeps the shell from exec-optimizing into sleep, so the
	// process we attack still carries an identifiable cmdline.
	script := "umask 022; echo made-in-sandbox > artifact.txt; mkdir -p .next/cache; echo x > .next/cache/chunk.js; env > env.txt; sleep 3; :"
	cmd, report, err := spawnSandbox(dir, []string{secret, "PATH=/usr/bin:/bin"},
		[]string{"/bin/sh", "-c", script})
	if err != nil {
		fail("spawn: %v", err)
	}

	rd := bufio.NewReader(report)
	line, err := rd.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "target ") {
		fail("no target report (line=%q err=%v)", line, err)
	}
	innerPid, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "target ")))

	// The shim lives in a new PID namespace, so the pid it reports is
	// meaningless on the host. Attacking it directly would test an unrelated
	// process and pass for the wrong reason — resolve the real host pid by
	// finding the shim's child.
	time.Sleep(500 * time.Millisecond)
	targetPid, err := findChildOf(cmd.Process.Pid)
	if err != nil {
		fail("resolving host pid of target (inner pid %d): %v", innerPid, err)
	}
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", targetPid))
	if !strings.Contains(string(cmdline), "made-in-sandbox") {
		fail("host pid %d is not our target (cmdline=%q)", targetPid, sanitize(cmdline))
	}
	targetUID := procUID(targetPid)
	fmt.Printf("target: inner pid %d = host pid %d, host kuid %d (real uid %d)\n",
		innerPid, targetPid, targetUID, os.Getuid())
	if targetUID == os.Getuid() {
		fail("target runs at the real uid — no isolation from same-UID readers")
	}

	// ATTACK 1: read the target's environment from outside (the same-UID
	// attacker position byn defends against).
	if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", targetPid)); err == nil {
		fail("ATTACK SUCCEEDED: /proc/%d/environ readable from outside", targetPid)
	} else if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		fmt.Printf("PASS environ unreadable from real UID (%v)\n", err)
	} else {
		fail("unexpected environ error: %v", err)
	}
	if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/mem", targetPid)); err == nil {
		fail("ATTACK SUCCEEDED: /proc/%d/mem readable", targetPid)
	} else {
		fmt.Printf("PASS mem unreadable (%v)\n", err)
	}

	// DURING the run, artifacts belong to the subuid (protected, but foreign).
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(dir, "artifact.txt"), &st); err == nil {
		fmt.Printf("info: mid-run artifact owner kuid=%d (foreign, pre-sweep)\n", st.Uid)
	}

	// Wait for the shim to finish target + sweep.
	line, err = rd.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "swept" {
		fail("sweep did not complete (line=%q err=%v)", line, err)
	}
	if err := cmd.Wait(); err != nil {
		fail("shim exit: %v", err)
	}

	// ACCEPTANCE: files are owned by the real user and deletable without root.
	for _, p := range []string{"artifact.txt", ".next/cache/chunk.js"} {
		if err := syscall.Stat(filepath.Join(dir, p), &st); err != nil {
			fail("stat %s: %v", p, err)
		}
		if int(st.Uid) != os.Getuid() {
			fail("%s owned by kuid %d, want %d", p, st.Uid, os.Getuid())
		}
	}
	fmt.Printf("PASS artifacts owned by real uid %d after sweep\n", os.Getuid())

	// The secret must actually have reached the child — otherwise the
	// unreadable-environ result above would be vacuous.
	envDump, err := os.ReadFile(filepath.Join(dir, "env.txt"))
	if err != nil {
		fail("reading child env dump: %v", err)
	}
	if !strings.Contains(string(envDump), secret) {
		fail("secret was never injected into the child (dump=%q)", strings.TrimSpace(string(envDump)))
	}
	fmt.Println("PASS secret was injected into the child (and still unreadable from outside)")
	if err := os.RemoveAll(filepath.Join(dir, ".next")); err != nil {
		fail("rm -rf .next failed: %v", err)
	}
	fmt.Println("PASS rm -rf .next as real user")
	fmt.Println("VERIFY OK — userns dual-map tier proven end to end")
}

// wrapperMain stands in for the user-facing `byn exec` process: a normal
// process at the real uid that owns the sandbox and blocks.
func wrapperMain() {
	dir := os.Args[2]
	cmd, report, err := spawnSandbox(dir,
		[]string{"PATH=/usr/bin:/bin", "SPIKE_SECRET=byn-spike-3f9a1c"},
		[]string{"/bin/sh", "-c", "sleep 300; :"})
	if err != nil {
		fail("wrapper: spawn: %v", err)
	}
	bufio.NewReader(report).ReadString('\n')
	time.Sleep(300 * time.Millisecond)
	hostPid, err := findChildOf(cmd.Process.Pid)
	if err != nil {
		fail("wrapper: resolve target: %v", err)
	}
	fmt.Printf("shim %d target %d\n", cmd.Process.Pid, hostPid)
	os.Stdout.Sync()
	time.Sleep(300 * time.Second)
}

// killtestMain proves teardown: killing the user-owned wrapper must take the
// protected shim and the target with it, with no manual cleanup.
func killtestMain() {
	dir, err := os.MkdirTemp("", "spike-kill-*")
	if err != nil {
		fail("mkdtemp: %v", err)
	}
	defer os.RemoveAll(dir)

	wrapper := exec.Command("/proc/self/exe", "wrapper", dir)
	stdout, err := wrapper.StdoutPipe()
	if err != nil {
		fail("pipe: %v", err)
	}
	wrapper.Stderr = os.Stderr
	if err := wrapper.Start(); err != nil {
		fail("start wrapper: %v", err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		fail("wrapper report: %v", err)
	}
	var shimPid, targetPid int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "shim %d target %d", &shimPid, &targetPid); err != nil {
		fail("parsing wrapper report %q: %v", line, err)
	}
	fmt.Printf("wrapper %d -> shim %d -> target %d\n", wrapper.Process.Pid, shimPid, targetPid)

	// Whether the user can signal the target directly follows from who owns
	// the namespace: the owner uid holds CAP_KILL inside it. Under the shippable
	// design (daemon-owned namespace) this must be EPERM.
	owner, err := nsOwnerUID(targetPid)
	if err != nil {
		fail("ns owner: %v", err)
	}
	killErr := syscall.Kill(targetPid, 0)
	if owner == os.Getuid() {
		fmt.Printf("NOTE userns owned by our uid %d, so signalling is permitted (err=%v).\n"+
			"     Expected only in the ownership-only tier; see `sandbox-spike attack`.\n", owner, killErr)
	} else if !errors.Is(killErr, syscall.EPERM) {
		fail("daemon-owned namespace but signalling the target gave %v, want EPERM", killErr)
	} else {
		fmt.Println("PASS target is not directly signalable by the real user (EPERM)")
	}

	// Kill only the wrapper, as Ctrl-C or `kill %1` would.
	if err := wrapper.Process.Kill(); err != nil {
		fail("kill wrapper: %v", err)
	}
	wrapper.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for {
		shimGone := syscall.Kill(shimPid, 0) != nil
		targetGone := syscall.Kill(targetPid, 0) != nil
		if shimGone && targetGone {
			fmt.Println("PASS killing the wrapper tore down shim and target (pdeathsig cascade)")
			fmt.Println("KILLTEST OK")
			return
		}
		if time.Now().After(deadline) {
			fail("leak: shimGone=%v targetGone=%v after wrapper death", shimGone, targetGone)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// nsOwnerUID reports which uid owns the user namespace a pid belongs to.
// Whoever owns it holds every capability inside it.
func nsOwnerUID(pid int) (int, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/ns/user", pid))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var owner uint32
	const nsGetOwnerUID = 0xb704
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		nsGetOwnerUID, uintptr(unsafe.Pointer(&owner))); errno != 0 {
		return 0, errno
	}
	return int(owner), nil
}

// attackMain is the adversarial test that decides whether the isolation is
// real. A user namespace grants ALL capabilities to the uid that owns it, so
// if byn's own wrapper (running as the user) creates the sandbox, any same-UID
// attacker can nsenter into it as inner-root and read the injected secrets.
// This must FAIL for a design to be shippable.
func attackMain() {
	dir, err := os.MkdirTemp("", "spike-attack-*")
	if err != nil {
		fail("mkdtemp: %v", err)
	}
	defer os.RemoveAll(dir)

	wrapper := exec.Command("/proc/self/exe", "wrapper", dir)
	stdout, err := wrapper.StdoutPipe()
	if err != nil {
		fail("pipe: %v", err)
	}
	wrapper.Stderr = os.Stderr
	if err := wrapper.Start(); err != nil {
		fail("start wrapper: %v", err)
	}
	defer func() { wrapper.Process.Kill(); wrapper.Wait() }()

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		fail("wrapper report: %v", err)
	}
	var shimPid, targetPid int
	fmt.Sscanf(strings.TrimSpace(line), "shim %d target %d", &shimPid, &targetPid)

	owner, err := nsOwnerUID(targetPid)
	if err != nil {
		fail("ns owner: %v", err)
	}
	fmt.Printf("sandbox userns owner uid=%d, our uid=%d\n", owner, os.Getuid())

	// Direct read must fail (different kuid) — this is the check that lulls
	// you into thinking the sandbox works.
	if _, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", targetPid)); err == nil {
		fail("direct environ read succeeded — no isolation at all")
	}
	fmt.Println("PASS direct /proc read is blocked")

	// The real attack: join the namespace as inner-root and read every
	// process's environment.
	out, _ := exec.Command("nsenter", "-t", strconv.Itoa(targetPid), "-U", "-p", "-m", "--",
		"/bin/sh", "-c",
		`for p in /proc/[0-9]*; do tr '\0' '\n' < $p/environ 2>/dev/null; done`).CombinedOutput()

	if strings.Contains(string(out), "SPIKE_SECRET") {
		fmt.Println("*** ATTACK SUCCEEDED: secret stolen by joining the user namespace ***")
		fmt.Printf("    owner uid %d == attacker uid %d, so the attacker is root inside the sandbox.\n",
			owner, os.Getuid())
		fmt.Println("    CONCLUSION: the namespace must be created by a process at a DIFFERENT uid")
		fmt.Println("    (the byn daemon under its own service user). A user-created namespace")
		fmt.Println("    protects nothing from same-UID attackers.")
		os.Exit(2)
	}
	fmt.Println("PASS namespace join did not expose the secret")
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: sandbox-spike probe|verify|killtest|attack|shim|wrapper")
	}
	switch os.Args[1] {
	case "probe":
		probeMain()
	case "verify":
		verifyMain()
	case "killtest":
		killtestMain()
	case "attack":
		attackMain()
	case "shim":
		shimMain()
	case "wrapper":
		wrapperMain()
	default:
		fail("unknown mode %q", os.Args[1])
	}
}
