package migrate

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LocalSource is an [ImportSource] backed by a directory on the local
// filesystem — the one implementation NU-6 ships. It is the source for both
// migrate modes: a legacy ~/.byn relocate and a `--from <dir>` import.
//
// It exposes only the byn state artifacts under its root (see
// [IsStateArtifact]) and refuses any read that would escape that root.
type LocalSource struct {
	root string
}

// NewLocalSource returns an ImportSource rooted at dir. The directory is not
// required to exist yet — that surfaces from List/Open so callers get one error
// path. dir is cleaned so the root is canonical for the escape check.
func NewLocalSource(dir string) *LocalSource {
	return &LocalSource{root: filepath.Clean(dir)}
}

// List walks the source root and returns the slash-relative paths of every byn
// state artifact, skipping ephemera (socket, pidfile, log, portal token,
// rate-limiter state, owner record, the sessions/ subtree, atomic-write temp
// files). The result is the contract a later adopt core consumes.
func (s *LocalSource) List() ([]string, error) {
	var out []string
	err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(s.root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if IsStateArtifact(rel) {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("migrate: list %s: %w", s.root, err)
	}
	return out, nil
}

// Open returns a reader for one artifact by its source-relative path. It
// rejects absolute paths and any path that escapes the root (e.g. "..") before
// touching the filesystem — a hostile or buggy caller must never read outside
// the source. The caller closes the returned reader.
func (s *LocalSource) Open(rel string) (io.ReadCloser, error) {
	abs, err := s.resolve(rel)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs) // #nosec G304 -- abs is confined to s.root by resolve()
	if err != nil {
		return nil, fmt.Errorf("migrate: open %s: %w", rel, err)
	}
	return f, nil
}

// resolve validates a source-relative path and returns the absolute path inside
// the root, or an error if the path is absolute or escapes the root. It is the
// single security gate both Open and any future per-file reader go through.
func (s *LocalSource) resolve(rel string) (string, error) {
	clean := normalizeRel(rel)
	if clean == "" {
		return "", fmt.Errorf("migrate: empty artifact path")
	}
	if filepath.IsAbs(rel) || filepath.IsAbs(filepath.FromSlash(rel)) {
		return "", fmt.Errorf("migrate: refusing absolute artifact path %q", rel)
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("migrate: refusing path escape %q", rel)
	}
	abs := filepath.Join(s.root, filepath.FromSlash(clean))
	// Defence in depth: confirm the joined path is genuinely under the root,
	// in case Clean/Join ever leaves a residual escape on some platform.
	rootPrefix := s.root + string(os.PathSeparator)
	if abs != s.root && !strings.HasPrefix(abs, rootPrefix) {
		return "", fmt.Errorf("migrate: refusing path escape %q", rel)
	}
	return abs, nil
}

// normalizeRel cleans a source-relative path to slash form for classification
// and comparison. It is intentionally lenient about leading "./" but preserves
// a leading ".." so resolve() can reject an escape.
func normalizeRel(rel string) string {
	rel = filepath.ToSlash(rel)
	rel = strings.TrimPrefix(rel, "./")
	// path.Clean collapses interior "." and ".." without OS path semantics,
	// keeping a leading ".." visible for the escape check in resolve().
	rel = filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
	if rel == "." {
		return ""
	}
	return rel
}
