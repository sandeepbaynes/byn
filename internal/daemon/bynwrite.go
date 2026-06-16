package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/privsep"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
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

// trustGrantPolicy carries the policy fields extracted from a parsed .byn,
// returned alongside the trust record identity so callers can surface them in
// responses (spec §4.5 footgun guard — show at approval).
type trustGrantPolicy struct {
	Actions         []string
	Auth            map[string]string
	Aliases         map[string]string
	EnvWildcard     bool
	ActionsWildcard bool
}

// putTrustRecordWithKey mints the fp + vk MACs from an already-derived vk-MAC
// key and records the FULL v2 trust record: canonical path, hash, mtime,
// snapshot (full file body), and the policy tables (Actions, Auth, Scope)
// parsed from the .byn at grant time.
//
// Parse or ValidateAuth failure ⇒ the grant is REFUSED (the returned error is
// non-nil, which the callers map to CodeBadRequest). A malformed .byn can no
// longer be silently trusted — this closes NU-1's trusted-but-malformed case
// at grant time (exec still guards at use-time for hand-crafted records).
//
// os.Stat failure after a successful ReadFile ⇒ the grant is also refused (no
// mtime=0 v2 records; fail closed — the caller should retry).
func (d *Daemon) putTrustRecordWithKey(ctx context.Context, st *vault.Store, vaultName, path string, body, vkKey, password []byte) (canon, hash string, changed bool, policy trustGrantPolicy, err error) {
	// Parse and validate BEFORE writing anything to the trust store.
	parsed, perr := bynfile.Parse(body)
	if perr != nil {
		return "", "", false, trustGrantPolicy{},
			fmt.Errorf("malformed .byn: %w", perr)
	}
	if verr := parsed.ValidateAuth(); verr != nil {
		return "", "", false, trustGrantPolicy{},
			fmt.Errorf("invalid [auth] in .byn: %w", verr)
	}
	if verr := parsed.ValidateActions(); verr != nil {
		return "", "", false, trustGrantPolicy{},
			fmt.Errorf("invalid [exec] actions in .byn: %w", verr)
	}
	if verr := parsed.ValidateAliases(); verr != nil {
		return "", "", false, trustGrantPolicy{},
			fmt.Errorf("invalid [aliases] in .byn: %w", verr)
	}

	canon = trust.Canonicalize(path)
	hash = trust.Hash(body)

	// os.Stat must succeed: a zero mtime would silently degrade to a v1
	// record. Fail closed so the caller can retry (the file just vanished).
	fi, serr := os.Stat(path) // #nosec G304 -- user-named; daemon reaches it via owner-granted ACL under privsep
	if serr != nil {
		return "", "", false, trustGrantPolicy{},
			fmt.Errorf("stat %s after read: %w (file may have been removed)", path, serr)
	}

	// Build the actions list (nil when empty/absent so omitempty works).
	var actions []string
	if len(parsed.Exec.Actions) > 0 {
		actions = []string(parsed.Exec.Actions)
	}
	// Build the auth map (nil when empty so omitempty works).
	var authMap map[string]string
	if len(parsed.Auth) > 0 {
		authMap = parsed.Auth
	}
	// Build the aliases map (nil when empty so omitempty works).
	var aliasMap map[string]string
	if len(parsed.Aliases) > 0 {
		aliasMap = parsed.Aliases
	}

	rec := trust.Record{
		Path:          canon,
		SHA256:        hash,
		Vault:         vaultName,
		MTimeUnixNano: fi.ModTime().UnixNano(),
		Snapshot:      string(body),
		Actions:       actions,
		Auth:          authMap,
		Aliases:       aliasMap,
		ScopeVault:    parsed.Scope.Vault,
		ScopeProject:  parsed.Scope.Project,
		ScopeEnv:      parsed.Scope.Env,
	}
	// Capture + seal the autonomous-exec capability — the allowlisted vars' row
	// keys wrapped under the machine-fingerprint K_cap — so trusted exec can
	// inject them with NO password/unlock (survives restart). Best-effort: nil
	// when there's no [exec] env allowlist or no machine fingerprint, in which
	// case exec falls back to a password. Set BEFORE SetMACs so it is MAC-bound.
	capScope := vault.Scope{
		Project: defaultIfEmpty(parsed.Scope.Project, vault.DefaultProjectName),
		Env:     defaultIfEmpty(parsed.Scope.Env, vault.DefaultEnvName),
	}
	capBlob, cerr := d.sealExecCapability(ctx, st, capScope, []string(parsed.Exec.Env), parsed.AllowsAll(), password)
	if cerr != nil {
		return "", "", false, trustGrantPolicy{}, fmt.Errorf("seal exec capability: %w", cerr)
	}
	rec.ExecCapability = capBlob
	rec.SetMACs(d.fpMACKey, vkKey)
	changed, err = trust.Put(d.cfg.Dir, rec)
	policy = trustGrantPolicy{
		Actions:         actions,
		Auth:            authMap,
		Aliases:         aliasMap,
		EnvWildcard:     parsed.AllowsAll(),
		ActionsWildcard: parsed.ActionsAllowAll(),
	}
	return canon, hash, changed, policy, err
}

// sealExecCapability captures the per-row keys for a .byn's allowlisted vars and
// seals them under the machine-fingerprint K_cap, producing the blob stored in
// the trust record for autonomous trusted exec. Returns nil (no capability —
// exec will require a password) when there are no allowlisted vars or the
// machine fingerprint is unavailable. A wildcard (env="*") allowlist captures
// every var currently in scope. Uses the password when supplied (locked grant),
// else the in-memory key (passkey grant — vault unlocked).
func (d *Daemon) sealExecCapability(ctx context.Context, st *vault.Store, scope vault.Scope, allow []string, wildcard bool, password []byte) ([]byte, error) {
	if d.fpMACKey == nil {
		return nil, nil // no machine fingerprint → no cold capability
	}
	names := allow
	if wildcard {
		infos, err := st.ListEnvVars(ctx, scope)
		if err != nil {
			return nil, scopeOptional(err)
		}
		names = make([]string, 0, len(infos))
		for _, m := range infos {
			names = append(names, m.Name)
		}
	}
	if len(names) == 0 {
		return nil, nil // nothing to inject → no capability
	}

	var rowKeys map[string][]byte
	var err error
	if len(password) > 0 {
		rowKeys, err = st.CaptureRowKeysWithPassword(ctx, password, scope, names)
	} else {
		rowKeys, err = st.CaptureRowKeys(ctx, scope, names)
	}
	if err != nil {
		return nil, scopeOptional(err)
	}
	defer func() {
		for _, k := range rowKeys {
			zeroBytes(k)
		}
	}()

	capKey, err := vcrypto.DeriveCapKey(d.fpMACKey)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(capKey)
	return vcrypto.SealCapability(capKey, rowKeys)
}

// scopeOptional maps a "scope doesn't exist yet" error (no such project/env in
// the vault) to nil — that scope simply has no vars to capture, so the .byn gets
// no capability rather than failing the grant. Other errors pass through.
func scopeOptional(err error) error {
	if errors.Is(err, vault.ErrProjectNotFound) || errors.Is(err, vault.ErrEnvNotFound) {
		return nil
	}
	return err
}

// aclRunner returns a runner that executes an ACL command (setfacl / chmod)
// WITHOUT a shell (exec.Command, not sh -c), so a project path containing
// shell metacharacters cannot inject. Combined output is captured and folded
// into the returned error so the best-effort caller can log a useful warning.
//
// When d.testACLRunner is non-nil (set by tests), it is returned directly so
// the test can record or stub ACL invocations without a real binary.
func (d *Daemon) aclRunner() func(name string, args ...string) error {
	if d.testACLRunner != nil {
		return d.testACLRunner
	}
	return func(name string, args ...string) error {
		// #nosec G204 -- name is a fixed binary ("setfacl"/"chmod") chosen by
		// the platform ACL code; args come from the trust record's project dir
		// and os.UserHomeDir(), not arbitrary user input, and run via
		// exec.Command (no shell) so path metacharacters cannot inject.
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// ownerHome returns the owner's home directory used as the traversal target for
// the _byn-exec ACL. In NU-5 the daemon runs as the OWNER, so os.UserHomeDir()
// is the owner's home — the dir the project lives under that is often 0700 and
// thus needs an execute-only (search) ACL for the exec child to traverse in.
//
// NU-6 will revisit this: once the daemon itself runs as _byn (not the owner),
// the home must be resolved from the trust record's owner, not the daemon's
// process environment.
func ownerHome() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// grantProjectACL is the best-effort trust-time hook that gives the _byn-exec
// service user access to the project dir the .byn lives in (rwX + default ACL)
// plus execute-only traversal on the owner's home. It is a NO-OP unless privsep
// is enabled (d.cfg.Privsep) — when off, zero ACL commands run and trust
// grant/untrust behavior is unchanged. Failure is logged but never fails the
// trust grant: the child simply won't have access and the exec fails clearly
// later. bynPath is the path to the .byn file (its dir = the project dir).
func (d *Daemon) grantProjectACL(bynPath string) {
	if !d.cfg.Privsep {
		return
	}
	projectDir := filepath.Dir(bynPath)
	if err := privsep.GrantProjectACL(d.aclRunner(), projectDir, ownerHome()); err != nil {
		log.Printf("byn: privsep ACL grant for %s failed (exec child may lack access): %v", projectDir, err)
	}
}

// revokeProjectACL is the untrust-time mirror of grantProjectACL: it removes the
// _byn-exec ACL entries from the project dir and the owner's home. No-op unless
// privsep is enabled; best-effort (failure is logged, never fails untrust).
func (d *Daemon) revokeProjectACL(bynPath string) {
	if !d.cfg.Privsep {
		return
	}
	projectDir := filepath.Dir(bynPath)
	if err := privsep.RevokeProjectACL(d.aclRunner(), projectDir, ownerHome()); err != nil {
		log.Printf("byn: privsep ACL revoke for %s failed: %v", projectDir, err)
	}
}

// authorizeTrustGrant is the SINGLE trust-authorization path shared by
// handleTrustGrant, handleTrustGrantBulk, and handleBynWrite (trust-now).
//
// It routes through the auth.Provider registry:
//   - Password present → "password" provider (works locked or unlocked);
//     derives the vk-MAC key with DeriveSubkeyWithPassword.
//   - PresenceToken present → "passkey" provider; vault MUST be unlocked
//     (needed for DeriveSubkey — same constraint as BynWrite's token path).
//   - Neither → CodeBadRequest "trusting requires the master password or a
//     passkey" (BynWrite's wording, kept for consistency).
//
// On success the caller receives the derived vk-MAC key and MUST defer
// zeroBytes(vkKey). On failure an error envelope is returned and vkKey is nil.
func (d *Daemon) authorizeTrustGrant(ctx context.Context, id, vaultName string, st *vault.Store, password, presenceToken []byte) (vkKey []byte, errEnv *ipc.Envelope) {
	switch {
	case len(password) > 0:
		// Route through the "password" provider; this handles rate-limit and
		// audit, identical to authorizeWithPassword.
		p, ok := d.authProviders.Lookup("password")
		if !ok {
			return nil, ipc.NewError(id, ipc.CodeInternal, "password provider not registered", "")
		}
		_, err := p.Verify(ctx, auth.VerifyRequest{
			Vault:    vaultName,
			Action:   "trust.grant",
			Password: password,
		})
		if le := mapProviderErr(id, err); le != nil {
			return nil, le
		}
		// Derive the vk-MAC key. Try the password-based path first (works
		// locked). If it fails and the vault is unlocked, use the in-memory
		// path — this is the EE-seam safety valve: an EE provider may approve
		// via a mechanism other than the master password (e.g. device approval),
		// so the password credential is not necessarily the real one.
		k, derr := st.DeriveSubkeyWithPassword(password, trust.VKMACKeyInfo)
		if derr != nil {
			if st.IsLocked() {
				// EE safety-valve: the provider APPROVED (e.g. via device
				// approval) but the supplied password is not the real master
				// password, so key derivation fails. On a locked vault the
				// in-memory path is unavailable — tell the user to unlock.
				if errors.Is(derr, vcrypto.ErrWrongPassword) {
					return nil, ipc.NewError(id, ipc.CodeLocked, "vault is locked",
						"unlock the vault, then trust (or supply the master password)")
				}
				return nil, internalErr(id, derr)
			}
			// Vault is unlocked — derive from the in-memory vault key.
			k, derr = st.DeriveSubkey(trust.VKMACKeyInfo)
			if derr != nil {
				return nil, internalErr(id, derr)
			}
		}
		return k, nil

	case len(presenceToken) > 0:
		// Route through the "passkey" provider; burns the token and checks
		// vault binding — same semantics as the former presenceTokens.consume.
		p, ok := d.authProviders.Lookup("passkey")
		if !ok {
			return nil, ipc.NewError(id, ipc.CodeInternal, "passkey provider not registered", "")
		}
		_, err := p.Verify(ctx, auth.VerifyRequest{
			Vault:         vaultName,
			Action:        "trust.grant",
			PresenceToken: presenceToken,
		})
		if err != nil {
			return nil, ipc.NewError(id, ipc.CodeBadRequest,
				"passkey authorization expired or invalid",
				"re-authenticate with your passkey, or use your password")
		}
		// Vault must be unlocked: DeriveSubkey requires the in-memory vault key.
		if st.IsLocked() {
			return nil, ipc.NewError(id, ipc.CodeLocked,
				"vault is locked", "unlock the vault, then trust")
		}
		k, derr := st.DeriveSubkey(trust.VKMACKeyInfo)
		if derr != nil {
			return nil, internalErr(id, derr)
		}
		return k, nil

	default:
		return nil, ipc.NewError(id, ipc.CodeBadRequest,
			"trusting requires the master password or a passkey",
			"enter your password or use a passkey")
	}
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
	// Determine content first: verbatim (Content field) or generated from
	// Scope+EnvVars. The vault name for trust targeting is derived AFTER this
	// step so that when Content is provided the parsed [scope].vault is used
	// as the authority (not the client-supplied Scope.Vault field, which the
	// studio omits for raw-mode writes).
	var content string
	if len(req.Content) > 0 {
		// Validate verbatim content before anything else; errors refuse the write.
		errs, _ := bynValidateContent(req.Content)
		if len(errs) > 0 {
			return ipc.NewError(env.ID, ipc.CodeBadRequest,
				fmt.Sprintf("invalid .byn content: [%s] %s", errs[0].Section, errs[0].Message),
				"fix the .byn content and retry")
		}
		content = string(req.Content)
	} else {
		content = bynFileContent(req.Scope, req.EnvVars)
	}

	// Derive the vault name for trust targeting:
	//   - Content path: parse the written content and use the [scope].vault
	//     field (defaultIfEmpty) — this is the correct authority; the client
	//     does not need to send a scope field in raw/verbatim mode.
	//   - Generated path: use req.Scope.Vault (set by the builder form).
	var name string
	if len(req.Content) > 0 {
		if parsed, perr := bynfile.Parse([]byte(content)); perr == nil && parsed.Scope.Vault != "" {
			name = parsed.Scope.Vault
		} else {
			name = vault.DefaultVaultName
		}
	} else {
		name = defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	}

	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	// Trust-now: authorize (master password OR a fresh passkey presence token)
	// and derive the vk-MAC key BEFORE touching the file or trust store, so a
	// bad credential changes nothing. Routes through the shared
	// authorizeTrustGrant helper — the single trust-authorization path.
	var vkKey []byte
	if req.Trust {
		k, le := d.authorizeTrustGrant(ctx, env.ID, name, st, req.Password, req.PresenceToken)
		if le != nil {
			return le
		}
		vkKey = k
		defer zeroBytes(vkKey)
	}

	path := filepath.Join(req.Dir, ".byn")
	if werr := os.WriteFile(path, []byte(content), 0o600); werr != nil { // #nosec G304 -- user-named dir; daemon runs as the same user
		return ipc.NewError(env.ID, ipc.CodeInternal,
			fmt.Sprintf("write %s: %v", path, werr), "check directory permissions")
	}
	resp := ipc.BynWriteResp{Path: path}
	if req.Trust {
		// Cap the generated content size before trusting (matching grant paths).
		if len(content) > bynfile.MaxSize {
			canon := trust.Canonicalize(path)
			d.auditEmit(ctx, name, audit.Event{
				Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeDenied,
				ErrorCode: string(ipc.CodeBadRequest), BynPath: canon,
			})
			return ipc.NewError(env.ID, ipc.CodeBadRequest,
				fmt.Sprintf(".byn exceeds 64KB (size=%d bytes)", len(content)),
				"reduce the .byn size before trusting it")
		}
		_, _, _, policy, terr := d.putTrustRecordWithKey(ctx, st, name, path, []byte(content), vkKey, req.Password)
		if terr != nil {
			canon := trust.Canonicalize(path)
			d.auditEmit(ctx, name, audit.Event{
				Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeDenied,
				ErrorCode: string(ipc.CodeBadRequest), BynPath: canon,
			})
			return ipc.NewError(env.ID, ipc.CodeBadRequest,
				fmt.Sprintf("trust refused: %v", terr),
				"fix the .byn before trusting it")
		}
		resp.Trusted = true
		resp.Actions = policy.Actions
		resp.Auth = policy.Auth
		resp.Aliases = policy.Aliases
		resp.EnvWildcard = policy.EnvWildcard
		resp.ActionsWildcard = policy.ActionsWildcard
		// Privsep: best-effort grant the exec service user access to the
		// project dir (no-op when privsep is off; never fails the grant).
		d.grantProjectACL(path)
		d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeOK})
	}
	d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpBynWrite), Outcome: audit.OutcomeOK})
	out, err := ipc.NewResponse(env.ID, resp)
	if err != nil {
		return internalErr(env.ID, err)
	}
	return out
}
