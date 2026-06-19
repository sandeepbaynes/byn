package daemon

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// handleListDir lists the subdirectories of req.Path (default: the OWNER's home
// directory) for the portal directory picker. The daemon only ever reveals
// directories the listing process can read. No vault access.
func (d *Daemon) handleListDir(env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ListDirReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	path := req.Path
	if path == "" {
		path = d.resolveOwnerHome()
	}
	path = filepath.Clean(path)

	info, serr := os.Stat(path)
	if serr != nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("stat %s: %v", path, serr), "pick an accessible directory")
	}
	if !info.IsDir() {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("%s is not a directory", path), "")
	}
	ents, rerr := os.ReadDir(path) // #nosec G304 -- user-named; daemon runs as the same user
	if rerr != nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("read %s: %v", path, rerr), "check directory permissions")
	}
	// Build results. When IncludeFiles is false, only directories are returned
	// (preserving the original directory-picker contract). When IncludeFiles is
	// true, regular files are included as well; IsDir distinguishes them.
	// Directories sort before files; within each group, entries sort by name.
	dirs := make([]ipc.DirEntry, 0, len(ents))
	files := make([]ipc.DirEntry, 0)
	for _, e := range ents {
		if e.IsDir() {
			dirs = append(dirs, ipc.DirEntry{Name: e.Name(), IsDir: true})
		} else if req.IncludeFiles && e.Type().IsRegular() {
			files = append(files, ipc.DirEntry{Name: e.Name(), IsDir: false})
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	dirs = append(dirs, files...)
	entries := dirs

	parent := filepath.Dir(path)
	if parent == path {
		parent = "" // at the filesystem root
	}
	resp, err := ipc.NewResponse(env.ID, ipc.ListDirResp{Path: path, Parent: parent, Entries: entries})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// resolveOwnerHome returns the OWNER's home directory — the default root for the
// portal's directory/file pickers (and import). Under privsep the daemon runs as
// the _byn service user, whose home is /var/empty, so a bare os.UserHomeDir()
// would start every picker there. Resolve the home of the allowlisted owner UID
// instead, falling back to the process home and finally "/".
func (d *Daemon) resolveOwnerHome() string {
	if d.ownerUID != 0 {
		if u, err := user.LookupId(strconv.FormatUint(uint64(d.ownerUID), 10)); err == nil && u.HomeDir != "" {
			return u.HomeDir
		}
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return "/"
}
