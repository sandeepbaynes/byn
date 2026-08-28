package daemon

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Pre-flight: answer "will this command run cleanly?" without running it.
//
// The failure this removes: a pipeline discovers three minutes in that one of
// its steps is not pinned, or that a variable it needs has no value. Both are
// knowable before anything starts, and both used to be discovered by hitting
// them. An agent about to run `make test` can now ask first.
//
// It answers and changes nothing. In particular it does NOT raise an approval:
// a question about what would happen must not queue a decision for a person,
// or checking becomes its own kind of noise.

// matchesPinnedAction reports whether argv matches any pinned action pattern,
// and which one.
//
// Shared with the real gate so the two cannot drift: a pre-flight that answers
// differently from the thing it predicts is worse than none, because it is
// believed. Both spellings of argv[0] are tried for the same reason the gate
// tries them — a symlinked project directory spells the same file two ways.
func matchesPinnedAction(actions, argv []string) (matched bool, pattern string) {
	if len(argv) == 0 {
		return false, ""
	}
	candidates := [][]string{argv}
	if resolved, err := filepath.EvalSymlinks(argv[0]); err == nil && resolved != argv[0] {
		alt := append([]string(nil), argv...)
		alt[0] = resolved
		candidates = append(candidates, alt)
	}
	for _, a := range actions {
		if a == "*" {
			return true, "*"
		}
		pat, perr := bynfile.ParseActionPattern(a)
		if perr != nil {
			continue // a bad pattern matches nothing, as at the gate
		}
		for _, cand := range candidates {
			if pat.Match(cand) {
				return true, a
			}
		}
	}
	return false, ""
}

// handleExecPreflight answers whether a command would run, and whether the
// variables it needs have values.
func (d *Daemon) handleExecPreflight(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ExecPreflightReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	out := ipc.ExecPreflightResp{Byn: trust.Canonicalize(req.Path)}

	body, fi, rerr := readBynFile(req.Path)
	if rerr != nil {
		out.Reason = "no_byn"
		return respondPreflight(env.ID, out)
	}
	// The file's own mtime, as the real gate passes it. Passing zero makes
	// Verify report every file as changed, which would have this answer "not
	// pinned" for a .byn that pins the command perfectly well.
	var mtime int64
	if fi != nil {
		mtime = fi.ModTime().UnixNano()
	}
	canon := trust.Canonicalize(req.Path)
	status, _, rec, verr := trust.Verify(d.cfg.Dir, canon, trust.Hash(body), mtime, d.fpMACKey, nil)
	if verr != nil {
		out.Reason = "untrusted"
		return respondPreflight(env.ID, out)
	}
	// A file whose bytes changed but whose authority did not is still trusted,
	// and the gate treats it that way — so this must too, or it would report a
	// pause for a command that runs. Reconciling here asks nobody anything: it
	// compares policies and stops, where the gate would go on to queue a
	// decision if the change were a widening.
	if status == trust.VerifyChanged {
		if effective, _, ok := reconcileChanged(rec, body); ok {
			rec = applyPolicy(rec, effective)
			status = trust.VerifyTrusted
		}
	}
	if status != trust.VerifyTrusted {
		// Saying WHICH beats reporting "unpinned": the next step is different.
		out.Reason = "untrusted"
		if status == trust.VerifyChanged {
			out.Reason = "changed"
		}
		return respondPreflight(env.ID, out)
	}

	// Expand an alias the same way exec does, so the answer is about the
	// command that would run rather than the name that was typed.
	argv := req.Argv
	if req.Alias != "" {
		expansion, ok := rec.Aliases[req.Alias]
		if !ok {
			out.Reason = "unknown_alias"
			return respondPreflight(env.ID, out)
		}
		argv = append(strings.Fields(expansion), req.Argv...)
		out.ResolvedArgv = argv
	}

	out.Actions = rec.Actions
	switch {
	case len(rec.Actions) == 0:
		out.Reason = "no_actions"
	default:
		if ok, pattern := matchesPinnedAction(rec.Actions, argv); ok {
			out.Pinned, out.MatchedAction = true, pattern
		} else {
			out.Reason = "no_match"
		}
	}

	// The other half of "will this launch cleanly": are the declared variables
	// actually there? One call answers both, because an agent that has to make
	// two will make neither.
	if f, perr := bynfile.Parse(body); perr == nil {
		scope := vault.Scope{
			Project: defaultIfEmpty(rec.ScopeProject, vault.DefaultProjectName),
			Env:     defaultIfEmpty(rec.ScopeEnv, vault.DefaultEnvName),
		}
		if st, serr := d.storeForVault(env.ID, rec.Vault); serr == nil && st != nil {
			if infos, lerr := st.ListEnvVars(ctx, scope); lerr == nil {
				have := make(map[string]struct{}, len(infos))
				for _, m := range infos {
					have[m.Name] = struct{}{}
				}
				optional := make(map[string]struct{}, len(f.Exec.Optional))
				for _, n := range f.Exec.Optional {
					optional[n] = struct{}{}
				}
				unattended := make(map[string]struct{})
				if d.authored != nil {
					k := authoredScopeKey(rec.Vault, scope, "")
					for _, n := range d.authored.UnattendedNamesFor(k.Vault, k.Project, k.Env) {
						unattended[n] = struct{}{}
					}
				}
				for _, n := range []string(f.Exec.Env) {
					if n == "*" {
						continue
					}
					_, present := have[n]
					_, isOptional := optional[n]
					switch {
					case present:
						if _, inv := unattended[n]; inv {
							out.UnattendedEnv = append(out.UnattendedEnv, n)
						}
					case isOptional:
						out.OptionalMissing = append(out.OptionalMissing, n)
					default:
						out.MissingEnv = append(out.MissingEnv, n)
					}
				}
			}
		}
	}
	return respondPreflight(env.ID, out)
}

func respondPreflight(id string, out ipc.ExecPreflightResp) *ipc.Envelope {
	resp, err := ipc.NewResponse(id, out)
	if err != nil {
		return internalErr(id, err)
	}
	return resp
}
