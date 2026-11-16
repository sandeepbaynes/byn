package daemon

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Unsecure values — the decisions. What one IS, and how it is stored, is in
// internal/vault/unsecure.go.
//
// The rule in one sentence: an unsecure value needs nothing to read, and a
// sealed value becomes unsecure only when someone proves they are present to
// say so. Everything below is that sentence applied to one code path.

// maxSecureSetNames bounds one request. Generous for a hand-typed list or a
// glob over a scope, and small enough that the response stays a list someone
// can read.
const maxSecureSetNames = 1024

// handleSecureSet moves entries between sealed and unsecure.
//
// The two directions are gated differently, on purpose:
//
//   - Making values UNSECURE publishes them to everything that can reach byn,
//     for good. It takes the master password or a presence token, every time.
//     A session does not satisfy it, and a .byn's [auth] policy cannot relax
//     it: both are standing arrangements, and this is not something to agree
//     to in advance. It is the same grade of act as granting trust.
//
//   - Making values SECURE takes access away. It is gated like any other
//     change to a stored value — a session will do — because the only thing a
//     hostile caller gains by it is breaking a tool that read the name freely,
//     and that is the fail-safe direction.
//
// Both need the vault key (one opens a value, the other seals one), so a
// locked vault needs the password itself rather than a presence token.
func (d *Daemon) handleSecureSet(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.SecureSetReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	op := "unsecure"
	if req.Secure {
		op = "secure"
	}
	if len(req.Names) == 0 {
		return badRequest(env.ID, errors.New("no names given"))
	}
	if len(req.Names) > maxSecureSetNames {
		return badRequest(env.ID, errors.New("too many names in one request"))
	}
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	deny := func(le *ipc.Envelope) *ipc.Envelope {
		for _, n := range req.Names {
			d.auditPlane(ctx, req.Scope, "env_var", n, op, le)
		}
		return le
	}

	var le *ipc.Envelope
	if req.Secure {
		le = d.authorizeAction(ctx, env.ID, vaultName, scope, st, "update", req.Password, req.PresenceToken)
	} else {
		le = d.authorizeActionAlways(ctx, env.ID, vaultName, st,
			"making a value unsecure needs the master password — it becomes readable by anything on this machine that can run byn",
			"supply the master password (a session is not enough for this)",
			req.Password, req.PresenceToken)
	}
	if le != nil {
		return deny(le)
	}

	var vk []byte
	if st.IsLocked() {
		if len(req.Password) == 0 {
			return deny(ipc.NewError(env.ID, ipc.CodeLocked,
				"changing how a value is stored needs the vault key, and the vault is locked",
				"byn unlock, or supply the master password"))
		}
		k, uerr := st.UnwrapVaultKey(req.Password)
		if uerr != nil {
			return deny(mapVaultErr(env.ID, uerr))
		}
		defer zero(k)
		vk = k
	}

	var changes []vault.SecureChange
	var err error
	if vk != nil {
		changes, err = st.SetEnvVarsSecureWithKey(ctx, vk, scope, req.Names, req.Secure)
	} else {
		changes, err = st.SetEnvVarsSecure(ctx, scope, req.Names, req.Secure)
	}
	if err != nil {
		return deny(secureSetErr(env.ID, err, scope))
	}

	var resp ipc.SecureSetResp
	for _, c := range changes {
		if !c.Changed {
			resp.Unchanged = append(resp.Unchanged, c.Name)
			continue
		}
		resp.Changed = append(resp.Changed, c.Name)
		d.auditPlane(ctx, req.Scope, "env_var", c.Name, op, nil)
	}
	sort.Strings(resp.Changed)
	sort.Strings(resp.Unchanged)
	if len(resp.Changed) > 0 {
		d.touchVault(req.Scope.Vault)
		// The decision was the owner's, made with a credential. Whatever
		// claim an agent had on these names as "its own" ended there, exactly
		// as it does when a person overwrites one.
		if d.authored != nil {
			k := authoredScopeKey(vaultName, scope, "")
			_ = d.authored.Forget(k.Vault, k.Project, k.Env, resp.Changed...)
		}
		// A value that was just sealed needs its key in every grant that may
		// inject it, or a locked daemon will allow the name and open nothing.
		d.refreshCapabilitiesWithKey(ctx, st, vk, vaultName, scope)
	}
	out, oerr := ipc.NewResponse(env.ID, resp)
	if oerr != nil {
		return internalErr(env.ID, oerr)
	}
	return out
}

// secureSetErr words a failed change so the caller knows which name stopped
// it and what to do about that one.
func secureSetErr(id string, err error, scope vault.Scope) *ipc.Envelope {
	var ne *vault.NameError
	if !errors.As(err, &ne) {
		return mapVaultErr(id, err)
	}
	switch {
	case errors.Is(ne.Err, vault.ErrInheritedEntry):
		return ipc.NewError(id, ipc.CodeBadRequest,
			ne.Name+" is inherited from the default env, so it is changed there — nothing was changed",
			"byn --project "+defaultIfEmpty(scope.Project, vault.DefaultProjectName)+
				" --env "+vault.DefaultEnvName+" secure|unsecure "+ne.Name)
	case errors.Is(ne.Err, vault.ErrNotFound):
		return ipc.NewError(id, ipc.CodeNotFound,
			ne.Name+" does not exist in "+scopeLabel(scope)+" — nothing was changed", "")
	case errors.Is(ne.Err, vault.ErrBadName):
		return ipc.NewError(id, ipc.CodeBadName, "invalid name: "+ne.Name, "")
	case errors.Is(ne.Err, vault.ErrPlainTampered):
		return tamperedErr(id, ne.Name)
	}
	return internalErr(id, err)
}

// unsecureValues returns the unsecure values of scope that want admits: every
// one when all is set, otherwise only the named ones. It needs no key, so it
// is the whole of what a run with no trust behind it can be given.
//
// withheld names what was asked for and exists but is sealed. Names with no
// value at all are in neither list; the caller reports those as missing, the
// same way a trusted run does.
//
// keys are a grant's authored keys, when the caller has one: with them a
// locked daemon can check each value's MAC, and a value that fails is an error
// for the whole run rather than something quietly left out.
func (d *Daemon) unsecureValues(ctx context.Context, st *vault.Store, scope vault.Scope,
	want []string, all bool, keys vault.PlainKeys) (values []ipc.ExecFetchValue, withheld []string, err error) {
	infos, err := st.ListEnvVars(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	wanted := nameSet(want)
	for _, info := range infos {
		if !all {
			if _, ok := wanted[info.Name]; !ok {
				continue
			}
		}
		if !info.Unsecure {
			withheld = append(withheld, info.Name)
			continue
		}
		e, ok, uerr := st.UnsecureEnvVarWithKeys(ctx, scope, info.Name, keys)
		if uerr != nil {
			return nil, nil, uerr
		}
		if !ok {
			// Sealed between the listing and the read. It is withheld, which
			// is what its owner just asked for.
			withheld = append(withheld, info.Name)
			continue
		}
		values = append(values, ipc.ExecFetchValue{Name: e.Name, Value: e.Value})
	}
	sort.Strings(withheld)
	return values, withheld, nil
}

// plainKeysFor gathers what a locked daemon has for checking unsecure values
// in scope: the authored key of any trusted .byn that governs it, and of one
// that governs the project's default env, which the scope inherits from. On an
// unlocked vault the store checks with the vault key and needs neither.
//
// Both may be empty — no grant covers the scope — and then a locked read is
// not checked, because there is nothing to check it with.
func (d *Daemon) plainKeysFor(st *vault.Store, vaultName string, scope vault.Scope) vault.PlainKeys {
	if !st.IsLocked() {
		return vault.PlainKeys{}
	}
	keys := vault.PlainKeys{Own: d.authoredKeyFor(vaultName, scope)}
	if defaultIfEmpty(scope.Env, vault.DefaultEnvName) != vault.DefaultEnvName {
		dflt := scope
		dflt.Env = vault.DefaultEnvName
		keys.Default = d.authoredKeyFor(vaultName, dflt)
	}
	return keys
}

func zeroPlainKeys(k vault.PlainKeys) {
	zeroBytes(k.Own)
	zeroBytes(k.Default)
}

// allUnsecure reports whether every name resolves, in scope, to an unsecure
// value. A name with no value is not unsecure: it could be given a sealed one
// tomorrow, and an answer of "yes" here is used to skip asking a person.
func (d *Daemon) allUnsecure(ctx context.Context, st *vault.Store, scope vault.Scope, names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		if _, ok, err := st.UnsecureEnvVar(ctx, scope, n); err != nil || !ok {
			return false
		}
	}
	return true
}

// unsecureRun describes a run that was handed unsecure values only.
type unsecureRun struct {
	// Reason is why the .byn's trust did not cover the run, in the words exec
	// would otherwise have refused with. Empty when the caller asked for
	// unsecure values only and trust was never consulted.
	Reason string
	// Withheld are the names the run asked for that exist and are sealed.
	Withheld []string
}

// canDegrade reports whether a run whose .byn is not trusted may go ahead on
// unsecure values instead of being refused.
//
// An alias may not. Its expansion comes from the trust record — a file nobody
// approved must not be what decides which command `byn exec deploy` runs — so
// without trust there is no command to run at all. Whether the CALLER will be
// the one running it is not decided here: when it will not, the answer is a
// redirect rather than a refusal, and unsecureExec gives it.
func canDegrade(req ipc.ExecFetchReq) bool {
	return req.Alias == "" && len(req.Argv) > 0
}

// unsecureExec authorizes a run on unsecure values alone.
//
// There is nothing to authorize, which is the point: every value it returns is
// one the caller could have read with `byn get`, so the run is exactly what
// the caller could assemble by hand. No credential, no trust, no unlocked
// vault, no [exec] actions gate — each of those guards the sealed values, and
// none are handed over.
//
// Two things follow from "the caller could do this itself", and both are
// enforced here:
//
//   - The command runs AS THE CALLER. Never under privilege separation: that
//     isolates a child holding secrets from the user who started it, and this
//     child holds none. So when the caller is not the one who will run it
//     (asCaller false: exec.authorize / exec.spawn), the answer is
//     unsecure_only — a redirect to exec.fetch, not a refusal.
//
//   - A .byn in scope still chooses the names, trusted or not. Its [exec] env
//     list is only a selection among public values, so reading it from an
//     unapproved file grants nothing — while ignoring it would put every
//     unsecure value in the scope into a program that asked for two.
//
// why is the reason trust did not cover the run ("" when the caller asked for
// unsecure values outright). body is the .byn's content if already read.
func (d *Daemon) unsecureExec(ctx context.Context, id string, req ipc.ExecFetchReq, st *vault.Store,
	scope vault.Scope, why string, body []byte, asCaller bool) (
	values []ipc.ExecFetchValue, argv []string, wildcard, noneDeclared bool, missing []string,
	run *unsecureRun, le *ipc.Envelope) {

	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	canon := ""
	if req.Path != "" {
		canon = trust.Canonicalize(req.Path)
	}
	fail := func(e *ipc.Envelope) ([]ipc.ExecFetchValue, []string, bool, bool, []string, *unsecureRun, *ipc.Envelope) {
		outcome, code := outcomeFor(e)
		d.auditEmit(ctx, vaultName, audit.Event{
			Op: "exec", Outcome: outcome, BynPath: canon, Command: req.Command, ErrorCode: code,
		})
		return nil, nil, false, false, nil, nil, e
	}
	if req.Alias != "" {
		return fail(ipc.NewError(id, ipc.CodeBadRequest,
			"an alias comes from a trusted .byn, so it cannot run on unsecure values alone",
			"byn exec --unsecure -- COMMAND"))
	}
	if len(req.Argv) == 0 {
		return fail(ipc.NewError(id, ipc.CodeBadRequest, "no command given", "byn exec -- COMMAND"))
	}
	if !asCaller {
		// Not audited: nothing was decided. The CLI comes straight back
		// through exec.fetch, and that call is the one that is recorded.
		return nil, nil, false, false, nil, nil, ipc.NewError(id, ipc.CodeUnsecureOnly,
			"only unsecure values can be injected here, and those run as you rather than under privilege separation",
			"")
	}

	var want, optional []string
	all := false
	switch {
	case len(req.Vars) > 0:
		vars, verr := adhocVars(req.Vars)
		if verr != nil {
			return fail(badRequest(id, verr))
		}
		want = vars
	case req.Path != "":
		if body == nil {
			b, _, rerr := readBynFile(canon)
			if rerr != nil {
				msg := canon + " could not be read, so byn cannot tell which values this command wants"
				if errors.Is(rerr, errDaemonAccessDenied) {
					msg = rerr.Error()
				}
				return fail(ipc.NewError(id, ipc.CodeTrustDenied, msg, ""))
			}
			body = b
		}
		f, perr := bynfile.Parse(body)
		if perr != nil {
			return fail(badRequest(id, perr))
		}
		want, optional = []string(f.Exec.Env), f.Exec.Optional
		all = f.AllowsAll()
		wildcard = all
		noneDeclared = !all && len(want) == 0
	default:
		all = true
	}

	var withheld []string
	if !noneDeclared {
		var verr error
		keys := d.plainKeysFor(st, defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName), scope)
		values, withheld, verr = d.unsecureValues(ctx, st, scope, want, all, keys)
		zeroPlainKeys(keys)
		if verr != nil {
			return fail(mapVaultErr(id, verr))
		}
	}
	// A name that is sealed was withheld, not missing. Reporting it as both
	// would send someone to set a value that is already there.
	held := nameSet(withheld)
	for _, n := range missingAllowlisted(want, optional, all, values) {
		if _, ok := held[n]; !ok {
			missing = append(missing, n)
		}
	}
	cmd := req.Command
	if len(withheld) > 0 {
		cmd += " (withheld " + strings.Join(withheld, ", ") + ")"
	}
	d.auditEmit(ctx, vaultName, audit.Event{
		Op: "exec.unsecure", Outcome: audit.OutcomeOK,
		Project: scope.Project, Env: scope.Env, BynPath: canon, Command: cmd,
	})
	d.recordExecRun(ctx, st, scope, req, req.Argv, values,
		d.unattendedAmong(ctx, st, req.Scope.Vault, scope, values))
	return values, req.Argv, wildcard, noneDeclared, missing, &unsecureRun{Reason: why, Withheld: withheld}, nil
}

// withoutUnsecureWidenings drops, from a changed .byn's delta, each request for
// a variable that is unsecure in scope, and reports how many it dropped. What
// is left is what a person actually has to decide. Anything that is not a plain
// named variable — a wildcard, an action, a writable path — is never dropped.
func (d *Daemon) withoutUnsecureWidenings(ctx context.Context, st *vault.Store, scope vault.Scope,
	delta trust.Delta) (trust.Delta, int) {
	rest := delta
	rest.Widenings = nil
	dropped := 0
	for _, w := range delta.Widenings {
		if w.Kind == "env" && w.Name != "" && d.allUnsecure(ctx, st, scope, []string{w.Name}) {
			dropped++
			continue
		}
		rest.Widenings = append(rest.Widenings, w)
	}
	return rest, dropped
}

// namesOf lists a name set's members.
func namesOf(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	return out
}
