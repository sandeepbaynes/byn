package daemon

import (
	"context"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Reading the record of what past runs were given.
//
// Two levels, deliberately separated. WHAT a run received — the names, the
// .byn, the command, the caller, the time — is metadata, and byn already lists
// names without a credential, so listing them here reveals nothing new. The
// VALUES are a different thing entirely: handing them over is reading secrets,
// and the run record must not become a second way to do that. Revealing is
// gated exactly as `byn get` is, audited as a read, and the caller is told
// plainly that values are being exposed.
func (d *Daemon) handleRunList(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.RunListReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)

	runs, err := st.ListExecRuns(ctx, req.Limit)
	if err != nil {
		return mapVaultErr(env.ID, err)
	}

	out := make([]ipc.RunEntry, 0, len(runs))
	for _, r := range runs {
		if req.ID != 0 && r.ID != req.ID {
			continue
		}
		e := ipc.RunEntry{
			ID: r.ID, At: r.At.Unix(), Byn: r.Meta.BynPath, Command: r.Meta.Command,
			CallerPID: r.Meta.CallerPID, CallerComm: r.Meta.CallerComm,
			CallerAgent: r.Meta.CallerAgent, CallerAgentComm: r.Meta.CallerAgentComm,
			Cwd:        r.Meta.CallerCwd,
			Unattended: r.Meta.Unattended,
			VarCount:   r.VarCount, SnapshotID: r.SnapshotID,
		}
		if req.ID != 0 && r.SnapshotID != 0 {
			names, nerr := st.SnapshotNames(ctx, r.SnapshotID)
			if nerr == nil {
				e.Names = names
			}
		}
		out = append(out, e)
	}

	// What became of each value — no values, so no credential. Deliberately
	// before the Reveal block: this is the answer to the audit question, and it
	// should be reachable without ever entering the one that prints secrets.
	if req.Diff {
		for i := range out {
			if out[i].SnapshotID == 0 {
				continue
			}
			st2, serr := st.SnapshotStatus(ctx, out[i].SnapshotID)
			if serr != nil {
				continue
			}
			out[i].Status = make(map[string]string, len(st2))
			for n, v := range st2 {
				out[i].Status[n] = string(v)
			}
			if len(out[i].Names) == 0 {
				names, nerr := st.SnapshotNames(ctx, out[i].SnapshotID)
				if nerr == nil {
					out[i].Names = names
				}
			}
		}
	}

	if req.Reveal {
		if req.ID == 0 {
			return ipc.NewError(env.ID, ipc.CodeBadRequest,
				"revealing values needs one run, not the whole list",
				"byn runs show <id> --reveal")
		}
		// Reading secrets, so it is gated as reading secrets — and recorded as
		// a read, because someone pulling every value a run held is exactly the
		// event an audit trail exists to show.
		if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, "get", req.Password, nil); le != nil {
			return le
		}
		// Authorized, but the values still need the vault key. Said once, here,
		// rather than discovered value by value: without this the reveal walked
		// every name, failed to open each one, and reported the whole run as
		// having been replaced since — telling an auditor that four secrets had
		// been rotated when nothing had changed but the lock.
		if st.IsLocked() {
			return ipc.NewError(env.ID, ipc.CodeLocked,
				"the vault is locked, so byn cannot open the values this run received",
				"byn unlock, then retry")
		}
		for i := range out {
			d.revealRunValues(ctx, st, &out[i])
			d.auditEmit(ctx, vaultName, audit.Event{
				Op: "run.reveal", Outcome: audit.OutcomeOK, BynPath: out[i].Byn,
				Command: "revealed " + itoa(len(out[i].Values)) + " value(s) from run " + itoa64(out[i].ID),
			})
		}
	}

	resp, rerr := ipc.NewResponse(env.ID, ipc.RunListResp{Entries: out})
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}

// revealRunValues fills in the values a run received, and names the ones byn
// can no longer show.
func (d *Daemon) revealRunValues(ctx context.Context, st *vault.Store, e *ipc.RunEntry) {
	if e.SnapshotID == 0 {
		return
	}
	names, err := st.SnapshotNames(ctx, e.SnapshotID)
	if err != nil {
		return
	}
	e.Names = names
	e.Values = make(map[string]string, len(names))
	// The same statuses the ungated verify reports, so the two can never
	// describe one run differently.
	if st2, serr := st.SnapshotStatus(ctx, e.SnapshotID); serr == nil {
		e.Status = make(map[string]string, len(st2))
		for n, v := range st2 {
			e.Status[n] = string(v)
		}
	}
	for _, n := range names {
		val, verr := st.OpenSnapshotValue(ctx, e.SnapshotID, n)
		switch {
		case verr != nil:
			// No value, and no guess at why: Status already says whether it was
			// replaced, deleted, or is simply unreadable. Inventing a second
			// account here is how "byn could not read this" became "this was
			// rotated" — a claim about the value's history that byn had not
			// established.
			if e.Status != nil {
				if _, ok := e.Status[n]; !ok {
					e.Status[n] = "unreadable"
				}
			}
		default:
			e.Values[n] = string(val)
		}
	}
}

func itoa(n int) string { return itoa64(int64(n)) }
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
