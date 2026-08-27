package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Policy is what a `.byn` actually asks for, separated from how it is written.
// Trust is granted against this rather than against the file's bytes, because
// the bytes change for reasons that carry no authority: a reordered list, an
// added comment, a reformatted table, or a `git checkout` that only rewrites
// mtimes. Pinning bytes meant every one of those blocked every command in the
// project until a human retyped the master password.
//
// Comparing policies instead lets byn ask the question that matters — does this
// file want MORE than what was approved? — and only then involve a human.
type Policy struct {
	Vault   string
	Project string
	Env     string

	// EnvGrants are the [exec] env allowlist entries: explicit names, or "*".
	EnvGrants []string
	// Actions are the pinned command patterns.
	Actions []string
	// Writable are extra directories the exec child may write.
	Writable []string
	// Aliases maps alias name to the command it expands to.
	Aliases map[string]string
	// Auth are per-operation gate overrides, e.g. get="none".
	Auth map[string]string
}

// NormalizePolicy returns p with every list sorted and de-duplicated and every
// empty value dropped, so that two files asking for the same thing compare
// equal regardless of how they were written.
func NormalizePolicy(p Policy) Policy {
	out := Policy{
		Vault:     p.Vault,
		Project:   p.Project,
		Env:       p.Env,
		EnvGrants: normalizeList(p.EnvGrants),
		Actions:   normalizeList(p.Actions),
		Writable:  normalizeList(p.Writable),
		Aliases:   normalizeMap(p.Aliases),
		Auth:      normalizeMap(p.Auth),
	}
	return out
}

func normalizeList(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func normalizeMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Hash is a stable fingerprint of the normalized policy. Two `.byn` files that
// request the same authority hash the same however they are formatted, which is
// what lets a comment edit or a branch switch pass without re-approval.
func (p Policy) Hash() string {
	n := NormalizePolicy(p)
	h := sha256.New()
	write := func(label, s string) {
		// hash.Hash.Write never returns an error, per its own contract.
		_, _ = fmt.Fprintf(h, "%s\x1f%s\x1e", label, s)
	}
	write("vault", n.Vault)
	write("project", n.Project)
	write("env", n.Env)
	for _, s := range n.EnvGrants {
		write("env_grant", s)
	}
	for _, s := range n.Actions {
		write("action", s)
	}
	for _, s := range n.Writable {
		write("writable", s)
	}
	for _, k := range sortedKeys(n.Aliases) {
		write("alias:"+k, n.Aliases[k])
	}
	for _, k := range sortedKeys(n.Auth) {
		write("auth:"+k, n.Auth[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Delta describes how a requested policy relates to the granted one.
type Delta struct {
	// Widenings are the specific ways the request asks for more authority than
	// was granted. Empty means the request is within what a human already
	// approved.
	Widenings []Widening
	// Narrowings are authority the request gives up. They never need approval —
	// nobody has to consent to being granted less — but they are reported so a
	// re-approval can show the full picture.
	Narrowings []string
	// ScopeChanged is true when the file now points at a different vault,
	// project, or env. That re-aims every grant at different data, so it always
	// needs a human even though it adds no entry to the lists.
	ScopeChanged bool
}

// Widening is one way a policy asks for more than was granted.
type Widening struct {
	Kind   string // "env", "action", "writable", "alias", "auth", "scope"
	Detail string // human-readable description of what is being asked for
	// Name is the bare thing being asked for, when the widening is about one
	// named item (currently: the variable, for Kind "env"). Callers that decide
	// per item read this rather than parsing Detail, which is prose meant for
	// people and free to change.
	Name     string
	HighRisk bool // true when granting it is unusually consequential
}

// NeedsApproval reports whether a human must see this change. Narrowing-only
// changes apply silently: reducing what a project can reach cannot surprise
// anyone, and making people re-authenticate for it teaches them that the prompt
// is noise.
func (d Delta) NeedsApproval() bool {
	return len(d.Widenings) > 0 || d.ScopeChanged
}

// HighRisk reports whether any widening is one of the consequential kinds, so
// the approval surface can render it differently from a routine addition.
func (d Delta) HighRisk() bool {
	for _, w := range d.Widenings {
		if w.HighRisk {
			return true
		}
	}
	return false
}

// ComparePolicies reports how requested relates to granted.
//
// The asymmetry is deliberate: anything the request adds is a widening and
// needs consent; anything it drops is a narrowing and does not. A wildcard is
// treated as strictly wider than any list of names, so a file cannot quietly
// trade three named variables for "*".
func ComparePolicies(granted, requested Policy) Delta {
	g, r := NormalizePolicy(granted), NormalizePolicy(requested)
	var d Delta

	if g.Vault != r.Vault || g.Project != r.Project || g.Env != r.Env {
		d.ScopeChanged = true
		d.Widenings = append(d.Widenings, Widening{
			Kind: "scope",
			Detail: fmt.Sprintf("scope moves from %s to %s",
				scopeLabel(g.Vault, g.Project, g.Env), scopeLabel(r.Vault, r.Project, r.Env)),
			HighRisk: true,
		})
	}

	// [exec] env. A wildcard subsumes every name, so granting "*" makes any
	// added name a non-event, while introducing "*" is itself the widening.
	gWild, rWild := hasWildcard(g.EnvGrants), hasWildcard(r.EnvGrants)
	switch {
	case rWild && !gWild:
		d.Widenings = append(d.Widenings, Widening{
			Kind:     "env",
			Detail:   `injects ALL scope variables via "*" — including any added later`,
			HighRisk: true,
		})
	case !rWild:
		for _, name := range added(g.EnvGrants, r.EnvGrants) {
			if gWild {
				continue // already covered by the granted wildcard
			}
			d.Widenings = append(d.Widenings, Widening{
				Kind:   "env",
				Name:   name,
				Detail: "injects " + name,
			})
		}
	}

	// [exec] actions. Same wildcard rule; a new pattern is new code allowed to
	// run credential-free, so it is always worth a human's attention.
	gaWild, raWild := hasWildcard(g.Actions), hasWildcard(r.Actions)
	switch {
	case raWild && !gaWild:
		d.Widenings = append(d.Widenings, Widening{
			Kind:     "action",
			Detail:   `runs ANY command re-auth-free via "*"`,
			HighRisk: true,
		})
	case !raWild:
		for _, a := range added(g.Actions, r.Actions) {
			if gaWild {
				continue
			}
			d.Widenings = append(d.Widenings, Widening{
				Kind:   "action",
				Detail: "runs " + a,
			})
		}
	}

	for _, w := range added(g.Writable, r.Writable) {
		d.Widenings = append(d.Widenings, Widening{
			Kind:     "writable",
			Detail:   "writes " + w,
			HighRisk: isSensitivePath(w),
		})
	}

	for _, name := range sortedKeys(r.Aliases) {
		if was, ok := g.Aliases[name]; !ok {
			d.Widenings = append(d.Widenings, Widening{
				Kind:   "alias",
				Detail: fmt.Sprintf("adds alias %s → %s", name, r.Aliases[name]),
			})
		} else if was != r.Aliases[name] {
			d.Widenings = append(d.Widenings, Widening{
				Kind:   "alias",
				Detail: fmt.Sprintf("alias %s now runs %s (was %s)", name, r.Aliases[name], was),
			})
		}
	}

	// [auth] overrides decide whether byn asks for the master password at all.
	// Relaxing one is the most consequential line a .byn can contain — get="none"
	// turns every secret in scope into something any process at the caller's UID
	// can print — so it is always high risk, never a routine list addition.
	for _, op := range sortedKeys(r.Auth) {
		was, ok := g.Auth[op]
		if ok && was == r.Auth[op] {
			continue
		}
		if isAuthRelaxation(was, r.Auth[op]) {
			d.Widenings = append(d.Widenings, Widening{
				Kind:     "auth",
				Detail:   fmt.Sprintf("stops requiring authorization for %q (%s)", op, r.Auth[op]),
				HighRisk: true,
			})
		}
	}

	for _, name := range removed(g.EnvGrants, r.EnvGrants) {
		d.Narrowings = append(d.Narrowings, "no longer injects "+name)
	}
	for _, a := range removed(g.Actions, r.Actions) {
		d.Narrowings = append(d.Narrowings, "no longer runs "+a)
	}
	for _, w := range removed(g.Writable, r.Writable) {
		d.Narrowings = append(d.Narrowings, "no longer writes "+w)
	}
	for _, name := range sortedKeys(g.Aliases) {
		if _, ok := r.Aliases[name]; !ok {
			d.Narrowings = append(d.Narrowings, "drops alias "+name)
		}
	}
	return d
}

func scopeLabel(vault, project, env string) string {
	parts := make([]string, 0, 3)
	for _, s := range []string{vault, project, env} {
		if s == "" {
			s = "-"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "/")
}

func hasWildcard(list []string) bool {
	for _, s := range list {
		if s == "*" {
			return true
		}
	}
	return false
}

// added returns entries present in b but not a (both normalized).
func added(a, b []string) []string {
	have := make(map[string]struct{}, len(a))
	for _, s := range a {
		have[s] = struct{}{}
	}
	var out []string
	for _, s := range b {
		if _, ok := have[s]; !ok && s != "*" {
			out = append(out, s)
		}
	}
	return out
}

func removed(a, b []string) []string { return added(b, a) }

// isAuthRelaxation reports whether moving from was to now lowers the bar. An
// absent previous value means the vault default applied, which is stricter than
// any explicit "none".
func isAuthRelaxation(was, now string) bool {
	rank := map[string]int{"always": 3, "": 2, "trusted": 1, "none": 0}
	wasRank, ok := rank[was]
	if !ok {
		wasRank = 2
	}
	nowRank, ok := rank[now]
	if !ok {
		return false // unrecognized value: not provably a relaxation
	}
	return nowRank < wasRank
}

// sensitivePathMarkers are directories whose contents are credentials in their
// own right; granting the exec child write access to one is not a routine
// tool-cache addition.
var sensitivePathMarkers = []string{
	".ssh", ".aws", ".gnupg", ".config/gh", ".kube", ".docker", ".git",
}

func isSensitivePath(p string) bool {
	clean := strings.TrimSuffix(strings.ReplaceAll(p, "\\", "/"), "/")
	for _, marker := range sensitivePathMarkers {
		if clean == marker || strings.HasSuffix(clean, "/"+marker) ||
			strings.Contains(clean, "/"+marker+"/") {
			return true
		}
	}
	return false
}

// EnvAllowlist returns the set of variable names this record's grant currently
// permits, or nil when the grant is a wildcard (every name is permitted) or no
// allowlist was recorded. Callers treat nil as "no restriction beyond the
// capability itself".
func (r Record) EnvAllowlist() map[string]struct{} {
	if len(r.EnvGrants) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(r.EnvGrants))
	for _, n := range r.EnvGrants {
		if n == "*" {
			return nil
		}
		out[n] = struct{}{}
	}
	return out
}
