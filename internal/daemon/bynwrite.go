package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// bynFileContent renders a .byn scope file: a [scope] table (empty fields
// omitted) and, when envVars is non-empty, an [exec] env allowlist. The output
// parses under discovery's strict schema.
func bynFileContent(scope ipc.Scope, envVars []string) string {
	var b strings.Builder
	b.WriteString("[scope]\n")
	if scope.Vault != "" {
		fmt.Fprintf(&b, "vault   = %q\n", scope.Vault)
	}
	if scope.Project != "" {
		fmt.Fprintf(&b, "project = %q\n", scope.Project)
	}
	if scope.Env != "" {
		fmt.Fprintf(&b, "env     = %q\n", scope.Env)
	}
	if len(envVars) > 0 {
		b.WriteString("\n[exec]\nenv = [")
		for i, v := range envVars {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", v)
		}
		b.WriteString("]\n")
	}
	return b.String()
}

// putTrustRecordWithKey mints the fp + vk MACs from an already-derived vk-MAC
// key and records {canonical path, hash}. Returns whether an existing record
// was replaced (a changed-hash re-approval).
func (d *Daemon) putTrustRecordWithKey(vaultName, path string, body, vkKey []byte) (canon, hash string, changed bool, err error) {
	canon = trust.Canonicalize(path)
	hash = trust.Hash(body)
	rec := trust.Record{Path: canon, SHA256: hash, Vault: vaultName}
	rec.SetMACs(d.fpMACKey, vkKey)
	changed, err = trust.Put(d.cfg.Dir, rec)
	return canon, hash, changed, err
}

// putTrustRecord derives the vk-MAC key from the (already-verified) password and
// records the trust. The caller MUST have verified the password first.
func (d *Daemon) putTrustRecord(st *vault.Store, vaultName, path string, body, password []byte) (canon, hash string, changed bool, err error) {
	vkKey, derr := st.DeriveSubkeyWithPassword(password, trust.VKMACKeyInfo)
	if derr != nil {
		return "", "", false, derr
	}
	defer zeroBytes(vkKey)
	return d.putTrustRecordWithKey(vaultName, path, body, vkKey)
}

// handleBynWrite writes a .byn into the requested directory (as Dir/.byn) and,
// when Trust is set, trusts it in the same step. Writing the file needs no auth
// (the same-UID owner could write it by hand); trusting it is password-gated,
// exactly like trust.grant.
func (d *Daemon) handleBynWrite(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.BynWriteReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zeroBytes(req.Password)
	if req.Dir == "" {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "directory required",
			"provide the project directory the .byn belongs in")
	}
	info, serr := os.Stat(req.Dir)
	if serr != nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("stat %s: %v", req.Dir, serr), "check the directory exists")
	}
	if !info.IsDir() {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("%s is not a directory", req.Dir), "provide a directory, not a file")
	}
	name := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	// Trust-now: authorize (master password OR a fresh passkey presence token)
	// and derive the vk-MAC key BEFORE touching the file or trust store, so a
	// bad credential changes nothing.
	var vkKey []byte
	if req.Trust {
		switch {
		case len(req.Password) > 0:
			if le := d.authorizeWithPassword(ctx, env.ID, name, st, req.Password); le != nil {
				return le
			}
			k, derr := st.DeriveSubkeyWithPassword(req.Password, trust.VKMACKeyInfo)
			if derr != nil {
				return internalErr(env.ID, derr)
			}
			vkKey = k
		case len(req.PresenceToken) > 0:
			if !d.presenceTokens.consume(req.PresenceToken, name, time.Now()) {
				return ipc.NewError(env.ID, ipc.CodeBadRequest,
					"passkey authorization expired or invalid", "re-authenticate with your passkey, or use your password")
			}
			if st.IsLocked() {
				return ipc.NewError(env.ID, ipc.CodeLocked, "vault is locked", "unlock the vault, then trust")
			}
			k, derr := st.DeriveSubkey(trust.VKMACKeyInfo)
			if derr != nil {
				return internalErr(env.ID, derr)
			}
			vkKey = k
		default:
			return ipc.NewError(env.ID, ipc.CodeBadRequest,
				"trusting requires the master password or a passkey", "enter your password or use a passkey")
		}
		defer zeroBytes(vkKey)
	}
	content := bynFileContent(req.Scope, req.EnvVars)
	path := filepath.Join(req.Dir, ".byn")
	if werr := os.WriteFile(path, []byte(content), 0o600); werr != nil { // #nosec G304 -- user-named dir; daemon runs as the same user
		return ipc.NewError(env.ID, ipc.CodeInternal,
			fmt.Sprintf("write %s: %v", path, werr), "check directory permissions")
	}
	resp := ipc.BynWriteResp{Path: path}
	if req.Trust {
		if _, _, _, terr := d.putTrustRecordWithKey(name, path, []byte(content), vkKey); terr != nil {
			return internalErr(env.ID, terr)
		}
		resp.Trusted = true
		d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeOK})
	}
	d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpBynWrite), Outcome: audit.OutcomeOK})
	out, err := ipc.NewResponse(env.ID, resp)
	if err != nil {
		return internalErr(env.ID, err)
	}
	return out
}
