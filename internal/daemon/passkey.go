package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/config"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/passkey"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// passkeyChallengeTTL bounds how long a begun ceremony may stay open before
// the follow-up finish must arrive.
const passkeyChallengeTTL = 2 * time.Minute

// passkeyChallenge is one in-flight ceremony's server-held state.
type passkeyChallenge struct {
	vault   string
	session *webauthn.SessionData
	salt    []byte // PRF eval salt for a registration (its unlock enrollment)
	expires time.Time
}

// passkeyChallenges is a TTL'd, one-time-use store of WebAuthn ceremony
// challenges. A challenge is consumed by the first take and never replayable.
type passkeyChallenges struct {
	mu sync.Mutex
	m  map[string]passkeyChallenge
}

func newPasskeyChallenges() *passkeyChallenges {
	return &passkeyChallenges{m: make(map[string]passkeyChallenge)}
}

// put stores a ceremony for vaultName (salt may be nil) and returns its
// one-time id.
func (c *passkeyChallenges) put(vaultName string, sess *webauthn.SessionData, salt []byte, now time.Time) (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked(now)
	c.m[id] = passkeyChallenge{vault: vaultName, session: sess, salt: salt, expires: now.Add(passkeyChallengeTTL)}
	return id, nil
}

// take removes and returns a ceremony, or ok=false if absent or expired.
func (c *passkeyChallenges) take(id string, now time.Time) (passkeyChallenge, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.m[id]
	if !ok {
		return passkeyChallenge{}, false
	}
	delete(c.m, id)
	if now.After(ch.expires) {
		return passkeyChallenge{}, false
	}
	return ch, true
}

func (c *passkeyChallenges) gcLocked(now time.Time) {
	for id, ch := range c.m {
		if now.After(ch.expires) {
			delete(c.m, id)
		}
	}
}

// passkeyRP builds the relying party bound to the portal's configured loopback
// origin (the URL the browser actually loads). rp.id stays "localhost"; only
// the origin carries the port, validated at finish against the response's
// clientDataJSON.
func (d *Daemon) passkeyRP() (*webauthn.WebAuthn, error) {
	port := d.cfg.UIPort
	if port == 0 {
		port = config.DefaultUIPort
	}
	return passkey.New(fmt.Sprintf("http://localhost:%d", port))
}

// passkeyUser loads a vault's enrolled credentials into a WebAuthn user. The
// stable per-vault handle is the vault id; the display name is the vault name.
func passkeyUser(ctx context.Context, st *vault.Store, vaultName string) (*passkey.User, error) {
	pks, err := st.Passkeys(ctx)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(pks))
	for _, pk := range pks {
		creds = append(creds, passkey.ToCredential(pk))
	}
	// The account name macOS surfaces in its passkey UI — byn-scoped per vault
	// so multiple vaults' passkeys are distinguishable under the shared
	// rp.id="localhost". The stable handle stays the vault id.
	return &passkey.User{ID: []byte(st.VaultID()), Name: "byn-" + vaultName, Creds: creds}, nil
}

// handlePasskeyRegisterBegin starts enrollment. Enrollment requires the vault
// unlocked — a byn vault always has a password, so "unlocked" is the
// proof-of-presence gate (no passkey-only access, ever).
func (d *Daemon) handlePasskeyRegisterBegin(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.PasskeyRegisterBeginReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.unlockedStoreForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	rp, err := d.passkeyRP()
	if err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, err.Error(), "open the portal with `byn web`")
	}
	u, err := passkeyUser(ctx, st, name)
	if err != nil {
		return internalErr(env.ID, err)
	}
	opts, sess, err := passkey.BeginRegistration(rp, u)
	if err != nil {
		return internalErr(env.ID, err)
	}
	// Per-credential PRF salt: ask the authenticator to enable PRF and (on
	// Apple) evaluate it at create(), so register-finish can wrap the vault key
	// with no second prompt. The raw salt is held in the ceremony; the browser
	// receives it base64url-encoded.
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return internalErr(env.ID, err)
	}
	opts.Response.Extensions = protocol.AuthenticationExtensions{
		"prf": map[string]any{"eval": map[string]any{"first": base64.RawURLEncoding.EncodeToString(salt)}},
	}
	return d.passkeyBeginResp(env.ID, name, sess, salt, opts, true)
}

// handlePasskeyRegisterFinish verifies the attestation and stores the credential.
func (d *Daemon) handlePasskeyRegisterFinish(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.PasskeyRegisterFinishReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.unlockedStoreForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	ch, ok := d.pkChallenges.take(req.CeremonyID, time.Now())
	if !ok || ch.vault != name {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "passkey ceremony expired or unknown", "restart enrollment")
	}
	rp, err := d.passkeyRP()
	if err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, err.Error(), "")
	}
	u, err := passkeyUser(ctx, st, name)
	if err != nil {
		return internalErr(env.ID, err)
	}
	cred, err := passkey.FinishRegistration(rp, u, ch.session, req.Response)
	if err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, fmt.Sprintf("passkey registration failed: %v", err), "")
	}
	pk := passkey.FromCredential(*cred)
	pk.Label = defaultIfEmpty(req.Label, "passkey")
	if err := st.AddPasskey(ctx, pk); err != nil {
		return mapVaultErr(env.ID, err)
	}
	// PRF cold-unlock enrollment: if the browser derived a KEK from the PRF
	// output, wrap a second copy of the vault key with it. No KEK → a
	// session-only passkey. The vault is unlocked here (enrollment gate), so
	// WrapVaultKey has the key.
	unlock := false
	if len(req.KEK) > 0 {
		wrapped, werr := st.WrapVaultKey(req.KEK, passkeyUnlockAAD(st.VaultID(), pk.CredentialID))
		if werr != nil {
			return internalErr(env.ID, werr)
		}
		if err := st.AddPasskeyUnlock(ctx, vault.PasskeyUnlock{
			CredentialID: pk.CredentialID, PRFSalt: ch.salt, WrappedVaultKey: wrapped, Label: pk.Label,
		}); err != nil {
			return mapVaultErr(env.ID, err)
		}
		unlock = true
	}
	d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpPasskeyRegisterFinish), Outcome: audit.OutcomeOK})
	resp, err := ipc.NewResponse(env.ID, ipc.PasskeyRegisterFinishResp{CredentialID: pk.CredentialID, Label: pk.Label, Unlock: unlock})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handlePasskeyAuthBegin starts an assertion. It works regardless of lock state
// — the whole point of passkey unlock is that the vault may be locked.
func (d *Daemon) handlePasskeyAuthBegin(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.PasskeyAuthBeginReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	rp, err := d.passkeyRP()
	if err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, err.Error(), "")
	}
	u, err := passkeyUser(ctx, st, name)
	if err != nil {
		return internalErr(env.ID, err)
	}
	if len(u.Creds) == 0 {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "no passkeys enrolled for this vault",
			"enroll one from the portal while the vault is unlocked")
	}
	opts, sess, err := passkey.BeginLogin(rp, u)
	if err != nil {
		return internalErr(env.ID, err)
	}
	// For credentials with a PRF-unlock record, ask the authenticator to
	// evaluate PRF with that credential's stored salt — so a good assertion
	// also yields the KEK that unwraps the vault key.
	if prf := d.passkeyUnlockPRF(ctx, st); prf != nil {
		opts.Response.Extensions = protocol.AuthenticationExtensions{"prf": prf}
	}
	return d.passkeyBeginResp(env.ID, name, sess, nil, opts, false)
}

// handlePasskeyAuthFinish verifies the assertion. In A-auth.1 this is session
// auth only (proof the holder is present); A-auth.2 will also unwrap the vault
// key here when the credential carries a PRF-derived KEK.
func (d *Daemon) handlePasskeyAuthFinish(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.PasskeyAuthFinishReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	ch, ok := d.pkChallenges.take(req.CeremonyID, time.Now())
	if !ok || ch.vault != name {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "passkey ceremony expired or unknown", "restart sign-in")
	}
	rp, err := d.passkeyRP()
	if err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, err.Error(), "")
	}
	u, err := passkeyUser(ctx, st, name)
	if err != nil {
		return internalErr(env.ID, err)
	}
	cred, err := passkey.FinishLogin(rp, u, ch.session, req.Response)
	if err != nil {
		d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpPasskeyAuthFinish), Outcome: audit.OutcomeDenied})
		return ipc.NewError(env.ID, ipc.CodeWrongPassword, fmt.Sprintf("passkey sign-in failed: %v", err), "")
	}
	if err := st.UpdatePasskeySignCount(ctx, cred.ID, cred.Authenticator.SignCount); err != nil {
		return mapVaultErr(env.ID, err)
	}
	// PRF cold-unlock: if the browser supplied a KEK and this credential has a
	// wrapped vault key, unwrap it to unlock the vault. A bad KEK fails closed
	// (vault stays locked) without failing the sign-in.
	unlocked := false
	if len(req.KEK) > 0 {
		if rec, lerr := st.PasskeyUnlockByCredentialID(ctx, cred.ID); lerr == nil {
			if uerr := st.UnlockWithKEK(req.KEK, rec.WrappedVaultKey, passkeyUnlockAAD(st.VaultID(), cred.ID)); uerr == nil {
				unlocked = true
				d.touchVault(name)
			}
		}
	}
	d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpPasskeyAuthFinish), Outcome: audit.OutcomeOK})
	resp, err := ipc.NewResponse(env.ID, ipc.PasskeyAuthFinishResp{CredentialID: cred.ID, Unlocked: unlocked})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handlePasskeyList returns the enrolled credentials (names + timestamps only,
// no secret), so it works while the vault is locked.
func (d *Daemon) handlePasskeyList(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.PasskeyListReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	pks, err := st.Passkeys(ctx)
	if err != nil {
		return mapVaultErr(env.ID, err)
	}
	out := make([]ipc.PasskeyInfo, 0, len(pks))
	for _, pk := range pks {
		_, uerr := st.PasskeyUnlockByCredentialID(ctx, pk.CredentialID)
		out = append(out, ipc.PasskeyInfo{
			CredentialID: pk.CredentialID, Label: pk.Label, CreatedAt: pk.CreatedAt.Unix(),
			Unlock: uerr == nil,
		})
	}
	resp, err := ipc.NewResponse(env.ID, ipc.PasskeyListResp{Passkeys: out})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handlePasskeyRemove revokes a credential. Password-gated (proof-of-presence),
// like trust grants — an ambient unlocked session is not consent.
func (d *Daemon) handlePasskeyRemove(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.PasskeyRemoveReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	if len(req.CredentialID) == 0 {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "credential_id required", "")
	}
	if len(req.Password) == 0 {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "removing a passkey requires the master password", "")
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeWithPassword(ctx, env.ID, name, st, req.Password); le != nil {
		return le
	}
	removed, err := st.DeletePasskey(ctx, req.CredentialID)
	if err != nil {
		return mapVaultErr(env.ID, err)
	}
	d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpPasskeyRemove), Outcome: audit.OutcomeOK})
	resp, err := ipc.NewResponse(env.ID, ipc.PasskeyRemoveResp{Removed: removed})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// passkeyBeginResp marshals the options, stores the challenge (with the PRF
// salt for a registration; nil for an assertion), and builds the begin response
// shared by register-begin and auth-begin.
func (d *Daemon) passkeyBeginResp(id, vaultName string, sess *webauthn.SessionData, salt []byte, opts any, register bool) *ipc.Envelope {
	cid, err := d.pkChallenges.put(vaultName, sess, salt, time.Now())
	if err != nil {
		return internalErr(id, err)
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return internalErr(id, err)
	}
	var body any
	if register {
		body = ipc.PasskeyRegisterBeginResp{CeremonyID: cid, Options: optsJSON}
	} else {
		body = ipc.PasskeyAuthBeginResp{CeremonyID: cid, Options: optsJSON}
	}
	resp, err := ipc.NewResponse(id, body)
	if err != nil {
		return internalErr(id, err)
	}
	return resp
}

// passkeyUnlockPRF builds the prf extension for an assertion. With a single
// unlock credential it uses the simpler `eval` form (broadest support —
// `evalByCredential` is flaky on some Chromium builds); with several it must
// use `evalByCredential` so each credential gets its own salt. nil when no
// credential can unlock.
func (d *Daemon) passkeyUnlockPRF(ctx context.Context, st *vault.Store) map[string]any {
	recs, err := st.PasskeyUnlocks(ctx)
	if err != nil || len(recs) == 0 {
		return nil
	}
	if len(recs) == 1 {
		return map[string]any{"eval": map[string]any{"first": base64.RawURLEncoding.EncodeToString(recs[0].PRFSalt)}}
	}
	ebc := make(map[string]any, len(recs))
	for _, r := range recs {
		ebc[base64.RawURLEncoding.EncodeToString(r.CredentialID)] = map[string]any{
			"first": base64.RawURLEncoding.EncodeToString(r.PRFSalt),
		}
	}
	return map[string]any{"evalByCredential": ebc}
}

// passkeyUnlockAAD binds a wrapped vault key to its vault + credential, so a
// wrap can never be replayed under a different credential or vault.
func passkeyUnlockAAD(vaultID string, credID []byte) []byte {
	const domain = "byn:passkey-unlock:v1"
	aad := make([]byte, 0, len(vaultID)+1+len(credID)+1+len(domain))
	aad = append(aad, vaultID...)
	aad = append(aad, 0x1F)
	aad = append(aad, credID...)
	aad = append(aad, 0x1F)
	aad = append(aad, domain...)
	return aad
}
