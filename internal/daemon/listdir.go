package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// handleListDir lists the subdirectories of req.Path (default: the user's home
// directory) for the portal directory picker. The daemon runs as the user, so
// it only ever reveals directories the user can already read. No vault access.
func (d *Daemon) handleListDir(env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ListDirReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	path := req.Path
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return internalErr(env.ID, err)
		}
		path = home
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
	dirs := make([]ipc.DirEntry, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			dirs = append(dirs, ipc.DirEntry{Name: e.Name()})
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })

	parent := filepath.Dir(path)
	if parent == path {
		parent = "" // at the filesystem root
	}
	resp, err := ipc.NewResponse(env.ID, ipc.ListDirResp{Path: path, Parent: parent, Entries: dirs})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}
