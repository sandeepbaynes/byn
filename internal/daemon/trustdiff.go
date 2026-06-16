package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// readBynFile reads a .byn file from path and enforces the 64 KiB size cap.
// Returns CodeBadRequest when the file is missing/unreadable (for diff; for
// grant paths use the caller-specific error handling) or exceeds the cap.
// The stat (for mtime) is returned separately so callers that need it don't
// have to re-stat.
//
// The daemon reads the REAL file deliberately: it is the security authority and
// validates the on-disk fingerprint itself rather than trusting content the
// (possibly compromised) CLI/UI supplies. Under privsep the daemon runs as _byn
// and reaches a user-owned .byn via the read ACL the owner CLI grants at trust
// time (privsep.GrantBynReadACL); without provisioning it runs owner-UID and
// reads directly.
func readBynFile(path string) (body []byte, fi os.FileInfo, err error) {
	f, err := os.Open(path) // #nosec G304 -- user-named; daemon reads via owner-granted ACL under privsep
	if err != nil {
		return nil, nil, annotateReadErr(path, err)
	}
	defer func() { _ = f.Close() }()

	fi, err = f.Stat()
	if err != nil {
		return nil, nil, err
	}

	if fi.Size() > bynfile.MaxSize {
		return nil, fi, fmt.Errorf(".byn exceeds 64KB (size=%d bytes)", fi.Size())
	}

	body = make([]byte, fi.Size())
	if _, err := io.ReadFull(f, body); err != nil {
		return nil, fi, err
	}
	return body, fi, nil
}

// annotateReadErr makes a macOS TCC denial actionable. The daemon runs as the
// _byn service user under launchd; macOS privacy protection (TCC) blocks it from
// open()ing files in protected locations (~/Documents, ~/Desktop, ~/Downloads,
// iCloud Drive) with EPERM even when POSIX permissions AND ACLs allow it —
// "operation not permitted", distinct from EACCES "permission denied". The fix
// is Full Disk Access for the daemon binary, or keeping projects outside those
// dirs. On other OSes / other errors the input error is returned UNCHANGED so
// callers' os.IsNotExist(err) checks keep working.
func annotateReadErr(path string, err error) error {
	if runtime.GOOS == "darwin" && errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("open %s: the byn daemon was denied by macOS privacy protection (TCC). "+
			"Fix EITHER by keeping the project outside ~/Documents, ~/Desktop, ~/Downloads and iCloud "+
			"(e.g. ~/code — no setup needed), OR by granting the byn binary Full Disk Access "+
			"(System Settings > Privacy & Security > Full Disk Access) and restarting the daemon "+
			"(sudo launchctl kickstart -k system/com.sandeepbaynes.byn). "+
			"Full steps incl. free code-signing so the grant persists: "+
			"`man byn` (macOS Full Disk Access) or docs/troubleshooting.md", path)
	}
	return err
}

// handleTrustDiff compares the current on-disk .byn content against the
// snapshot recorded at grant time. This is a read-only op (no password)
// that is audited. It is the backing handler for `byn trust diff <path>`.
//
// Error cases:
//   - no trust record → CodeNotFound "not trusted", recover "byn trust <path>"
//   - record has no snapshot (v1) → CodeBadRequest with re-trust hint
//   - file gone or unreadable → CodeNotFound
//   - file > 64 KiB → CodeBadRequest
func (d *Daemon) handleTrustDiff(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.TrustDiffReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	if req.Path == "" {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "path required", "")
	}

	canon := trust.Canonicalize(req.Path)

	// Look up the trust record.
	store, err := trust.Load(d.cfg.Dir)
	if err != nil {
		d.auditEmit(ctx, vault.DefaultVaultName, audit.Event{
			Op: string(ipc.OpTrustDiff), Outcome: audit.OutcomeError,
			BynPath: canon, ErrorCode: string(ipc.CodeInternal),
		})
		return internalErr(env.ID, err)
	}

	var rec *trust.Record
	for i := range store.Records {
		if store.Records[i].Path == canon {
			rec = &store.Records[i]
			break
		}
	}

	if rec == nil {
		d.auditEmit(ctx, vault.DefaultVaultName, audit.Event{
			Op: string(ipc.OpTrustDiff), Outcome: audit.OutcomeDenied,
			BynPath: canon, ErrorCode: string(ipc.CodeNotFound),
		})
		return ipc.NewError(env.ID, ipc.CodeNotFound,
			fmt.Sprintf("%s is not trusted", canon),
			"byn trust "+canon)
	}

	// Emit audit for this read-only op, using the vault from the record
	// (or the default if empty/v1).
	emitAudit := func(outcome, code string) {
		d.auditEmit(ctx, defaultIfEmpty(rec.Vault, vault.DefaultVaultName), audit.Event{
			Op: string(ipc.OpTrustDiff), Outcome: outcome,
			BynPath: canon, ErrorCode: code,
		})
	}

	if !rec.IsV2() {
		emitAudit(audit.OutcomeDenied, string(ipc.CodeBadRequest))
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("%s: trust record predates snapshots — re-trust to enable diff", canon),
			"byn trust "+canon)
	}

	// Read current file (enforcing the size cap).
	body, fi, rerr := readBynFile(canon)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			emitAudit(audit.OutcomeDenied, string(ipc.CodeNotFound))
			return ipc.NewError(env.ID, ipc.CodeNotFound,
				fmt.Sprintf("%s: file is gone", canon),
				"byn trust "+canon+" to re-record a new location, or byn untrust "+canon)
		}
		// size cap or other read error
		emitAudit(audit.OutcomeDenied, string(ipc.CodeBadRequest))
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("%s: %v", canon, rerr),
			"fix the .byn file before diffing")
	}

	oldSnap := []byte(rec.Snapshot)
	mtimeOnly := bytes.Equal(oldSnap, body) && fi != nil && fi.ModTime().UnixNano() != rec.MTimeUnixNano

	emitAudit(audit.OutcomeOK, "")
	resp, err := ipc.NewResponse(env.ID, ipc.TrustDiffResp{
		Path:             canon,
		Trusted:          true,
		OldSnapshot:      oldSnap,
		NewContent:       body,
		MTimeChangedOnly: mtimeOnly,
	})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}
