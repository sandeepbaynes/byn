package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAssets_DotenvCommentsJS runs the portal's .env parser and comment
// renderer under node against the same cases cmd/byn/dotenv_annotations_test.go
// holds for the CLI. The two implementations must read and write the format
// identically: a file exported from one is imported by the other. Skipped, not
// failed, where node is missing — the same bargain as TestAssets_JSSyntax.
func TestAssets_DotenvCommentsJS(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not in PATH — skipping portal .env parser check")
	}
	js, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	src := string(js)
	a := strings.Index(src, "const COMMENTED_ASSIGNMENT")
	b := strings.Index(src, "async function loadEntries()")
	if a < 0 || b < a {
		t.Fatal("app.js: .env comment helpers not found where expected")
	}
	lib := strings.Replace(src[a:b], "const COMMENTED_ASSIGNMENT", "var COMMENTED_ASSIGNMENT", 1)

	script := lib + dotenvJSCases
	path := filepath.Join(t.TempDir(), "dotenv_check.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(nodePath, path).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("portal .env parser disagrees with the format:\n%s", out)
	}
}

const dotenvJSCases = `
const fails = [];
const eq = (got, want, name) => {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g !== w) fails.push(name + ": got " + g + " want " + w);
};
const ann = (text, i) => parseDotenv(text)[i || 0][2];

eq(ann("# the staging key\n## acct 1234\n## rotated in May\nAPI_KEY=abc\nPLAIN=1\n"),
  { desc: "the staging key", notes: ["acct 1234", "rotated in May"] }, "description and notes");
eq(ann("# d\nA=1\nB=2\n", 1), { desc: "", notes: [] }, "a block belongs to one variable");
eq(ann("# line one\n#\n#   indented\n# line three\nK=v\n").desc,
  "line one\n\n  indented\nline three", "several # lines are one description");
eq(ann("# desc\n## note one\n# stray\n## note two\nK=v\n"),
  { desc: "desc", notes: ["note one", "note two"] }, "# after a note is dropped");
eq(ann("### a note\n##no space\n##\nK=v\n").notes, ["a note", "no space"], "### is a note");
eq(ann("# Database settings\n\nDB_URL=x\n"), { desc: "", notes: [] }, "blank line ends the block");
for (const l of ["# OLD_KEY=sk_live_123", "#export OLD_KEY=x", "# app.port = 80"]) {
  eq(ann("# about the old key\n" + l + "\nNEW_KEY=v\n"), { desc: "", notes: [] }, "commented-out " + l);
}
eq(ann("# set to 1 when a=b\nK=v\n").desc, "set to 1 when a=b", "prose with = is a description");
eq(ann("## only a note\nK=v\n"), { desc: "", notes: ["only a note"] }, "notes without description");

eq(annotationComments({ desc: "first\n\nthird  ", notes: ["one", "two\nlines", "   "] }),
  ["# first", "#", "# third", "## one", "## two lines"], "render");
const rt = { desc: "staging only\n# not a heading", notes: ["acct 1234", "#tagged"] };
eq(ann(annotationComments(rt).join("\n") + "\nK=v\n"), rt, "round trip");
eq(parseDotenv('K="a\\"b"\n')[0][1], 'a"b', "quoted values still unquote");

console.log(fails.length ? fails.join("\n") : "ok");
`
