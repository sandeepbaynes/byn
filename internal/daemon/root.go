package daemon

import "errors"

// errRefuseRoot is the loud, actionable refusal returned when the daemon would
// start as uid 0 without an explicit override. It explains WHY (a root daemon
// makes the _byn privsep separation meaningless — least-privilege) and HOW to
// proceed (don't run as root, or pass --allow-root to override — NOT
// recommended).
//
// Honest scope: this is posture hygiene, NOT a defense against an attacker who
// already has root (root can ptrace the daemon, task_for_pid it, read its
// memory regardless). It only stops the *operator* from negating their own
// privsep by accidentally launching the daemon as root. The message must not
// over-claim a security guarantee it cannot make.
var errRefuseRoot = errors.New(
	"byn daemon refuses to run as root (uid 0): a root daemon defeats the " +
		"_byn privilege separation it installs — privsep wants a dedicated, " +
		"unprivileged service user, not root (least privilege). " +
		"Run the daemon as a normal user (or let `byn setup` install the system " +
		"service as _byn); to override anyway, pass --allow-root (NOT recommended " +
		"— this is posture hygiene, not a defense against an existing root attacker)",
)

// refuseRoot is a pure predicate: it returns errRefuseRoot when the daemon
// would run with effective uid 0 and the operator has not explicitly opted in
// with allowRoot; otherwise nil. euid is passed in (not read from the OS) so
// every branch is unit-testable without actually running as root.
func refuseRoot(euid int, allowRoot bool) error {
	if euid == 0 && !allowRoot {
		return errRefuseRoot
	}
	return nil
}
