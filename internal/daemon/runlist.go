package daemon

import (
	"context"
	"errors"
	"sort"

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
			CallerAgent: r.Meta.CallerAgent, Cwd: r.Meta.CallerCwd,
			VarCount: r.VarCount, SnapshotID: r.SnapshotID,
		}
		if req.ID != 0 && r.SnapshotID != 0 {
			names, nerr := st.SnapshotNames(ctx, r.SnapshotID)
			if nerr == nil {
				e.Names = names
			}
		}
		out = append(out, e)
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
	for _, n := range names {
		val, verr := st.OpenSnapshotValue(ctx, e.SnapshotID, n)
		switch {
		case errors.Is(verr, vault.ErrValueSuperseded):
			// The value has been replaced since. byn keeps no copy of the old
			// one, so it says which rather than showing today's in its place.
			e.Superseded = append(e.Superseded, n)
		case verr != nil:
			e.Superseded = append(e.Superseded, n)
		default:
			e.Values[n] = string(val)
		}
	}
	sort.Strings(e.Superseded)
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
