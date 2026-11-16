package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// A marker is the whole line, single hash, any case — and belongs to the one
// variable below it.
func TestParseDotenv_UnsecureMarker(t *testing.T) {
	in := strings.Join([]string{
		"# unsecure",
		"# the port the dev server listens on",
		"PORT=8080",
		"",
		"#Unsecure",
		"REGION=eu-west-1",
		"NEXT_ONE=sealed-because-the-marker-does-not-carry",
		"",
		"# unsecure",
		"",
		"AFTER_BLANK=sealed-because-a-blank-line-ends-the-block",
		"",
		"# unsecure by default in dev",
		"SENTENCE=sealed-because-that-is-a-description",
		"",
		"## unsecure",
		"NOTE=sealed-because-that-is-a-note",
		"",
		"# SECURE",
		"KEPT=explicitly-sealed",
		"",
		"## a note first",
		"# unsecure",
		"AFTER_NOTE=marker-counts-anywhere-in-the-block",
	}, "\n")
	entries, err := parseDotenv([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]entryAnnotations{}
	for _, e := range entries {
		got[e.k] = e.ann
	}
	for name, want := range map[string]string{
		"PORT": markerUnsecure, "REGION": markerUnsecure, "NEXT_ONE": "",
		"AFTER_BLANK": "", "SENTENCE": "", "NOTE": "", "KEPT": markerSecure,
		"AFTER_NOTE": markerUnsecure,
	} {
		if got[name].marker != want {
			t.Errorf("%s: marker = %q, want %q", name, got[name].marker, want)
		}
	}
	// The marker is an instruction, never text about the variable.
	if d := got["PORT"].desc; d != "the port the dev server listens on" {
		t.Errorf("PORT description = %q", d)
	}
	if d := got["REGION"].desc; d != "" {
		t.Errorf("REGION description = %q, want none", d)
	}
	if d := got["SENTENCE"].desc; d != "unsecure by default in dev" {
		t.Errorf("SENTENCE description = %q", d)
	}
}

// What export writes, import reads back the same way.
func TestDotenv_UnsecureRoundTrip(t *testing.T) {
	out := renderDotenvAnnotated([]string{"API_KEY", "PORT"},
		map[string]string{"API_KEY": "s3cret", "PORT": "8080"},
		map[string]entryAnnotations{"PORT": {desc: "dev port", marker: markerUnsecure}})
	if !strings.Contains(out, "# unsecure\n# dev port\nPORT=8080\n") {
		t.Fatalf("export did not mark PORT:\n%s", out)
	}
	entries, err := parseDotenv([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	set, err := importUnsecureSet(entries, "")
	if err != nil {
		t.Fatal(err)
	}
	if !set["PORT"] || set["API_KEY"] {
		t.Fatalf("unsecure set = %v, want PORT only", set)
	}
}

func TestImportUnsecureSet(t *testing.T) {
	entries := []kv{
		{k: "PORT"}, {k: "LOG_LEVEL"}, {k: "LOG_KEY", ann: entryAnnotations{marker: markerSecure}},
		{k: "API_KEY"}, {k: "MARKED", ann: entryAnnotations{marker: markerUnsecure}},
	}
	set, err := importUnsecureSet(entries, "PORT, LOG_*")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"PORT": true, "LOG_LEVEL": true, "MARKED": true}
	if !reflect.DeepEqual(set, want) {
		t.Fatalf("set = %v, want %v (a `# secure` marker overrules a pattern)", set, want)
	}
	// With no patterns and no markers, nothing is unsecure.
	if set, _ := importUnsecureSet([]kv{{k: "A"}, {k: "B"}}, ""); len(set) != 0 {
		t.Fatalf("default set = %v, want empty", set)
	}
	// A pattern that matches nothing is a typo, not a no-op.
	if _, err := importUnsecureSet(entries, "PROT"); err == nil {
		t.Fatal("a pattern matching nothing was accepted")
	}
	if _, err := importUnsecureSet(entries, "[bad"); err == nil {
		t.Fatal("a malformed pattern was accepted")
	}
}

func TestPlanSecureSet(t *testing.T) {
	secrets := []ipc.SecretMeta{
		{Name: "PORT", Source: "scope"},
		{Name: "LOG_LEVEL", Source: "scope", Unsecure: true},
		{Name: "LOG_FORMAT", Source: "default"},
		{Name: "API_KEY", Source: "scope"},
	}
	plan, err := planSecureSet([]string{"PORT", "LOG_*", "PORT"}, secrets, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.change, []string{"PORT"}) ||
		!reflect.DeepEqual(plan.already, []string{"LOG_LEVEL"}) ||
		!reflect.DeepEqual(plan.inherited, []string{"LOG_FORMAT"}) {
		t.Fatalf("plan = %+v", plan)
	}
	// An exact name is always sent on, so the daemon can refuse it precisely.
	plan, err = planSecureSet([]string{"LOG_FORMAT", "NOPE"}, secrets, false)
	if err != nil || !reflect.DeepEqual(plan.change, []string{"LOG_FORMAT", "NOPE"}) {
		t.Fatalf("plan = %+v err = %v", plan, err)
	}
	if _, err := planSecureSet([]string{"ZZZ_*"}, secrets, false); err == nil {
		t.Fatal("a glob matching nothing was accepted")
	}
	// The other direction: sealing what is unsecure.
	plan, _ = planSecureSet([]string{"*"}, secrets, true)
	if !reflect.DeepEqual(plan.change, []string{"LOG_LEVEL"}) {
		t.Fatalf("secure plan = %+v", plan)
	}
}

func TestSecretLookingNames(t *testing.T) {
	got := secretLookingNames([]string{"PORT", "STRIPE_SECRET", "db_password", "LOG_LEVEL", "SIGNING_KEY", "KEYBOARD_LAYOUT"})
	want := []string{"STRIPE_SECRET", "db_password", "SIGNING_KEY"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
