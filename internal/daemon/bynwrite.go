package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
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
func (d *Daemon) putTrustRecordWithKey(vaultName, path string, body, vkKey []byte) (canon, hash string, changed bool, policy trustGrantPolicy, err error) {
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
	fi, serr := os.Stat(path) // #nosec G304 -- user-named; daemon runs as the same user
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
	name := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
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
	content := bynFileContent(req.Scope, req.EnvVars)
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
		_, _, _, policy, terr := d.putTrustRecordWithKey(name, path, []byte(content), vkKey)
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
		d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeOK})
	}
	d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpBynWrite), Outcome: audit.OutcomeOK})
	out, err := ipc.NewResponse(env.ID, resp)
	if err != nil {
		return internalErr(env.ID, err)
	}
	return out
}
